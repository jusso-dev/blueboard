using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Blueboard.Api.Http;

/// <summary>
/// REST API for the React app, called cross-origin from the web app with an Entra bearer token (CORS allows only the web origin).
/// Every route needs Board.Post (Board.Admin for reports), except /me which tells a role-less user why.
/// </summary>
public sealed class BoardApi(Endpoint ep, BoardService board, Search search, Reporting reporting, Broker broker, Enrichment enrich, Db db, Policy policy)
{
    private static string? Q(HttpRequest r, string k) => r.Query[k].ToString() is { Length: > 0 } v ? v : null;
    private static long? Long(HttpRequest r, string k) => long.TryParse(Q(r, k), out var v) ? v : null;
    private static int Int(HttpRequest r, string k, int d) => int.TryParse(Q(r, k), out var v) ? v : d;
    private static DateTimeOffset? Date(HttpRequest r, string k) =>
        Q(r, k) is { } s ? (DateTimeOffset.TryParse(s, out var d) ? d : throw new BoardException($"invalid {k}")) : null;
    private static string[]? Many(HttpRequest r, string k) =>
        r.Query[k].Count > 0 ? r.Query[k].OfType<string>().Where(v => v.Length > 0).ToArray() : null;
    private static Guid Id(string s) => Guid.TryParse(s, out var g) ? g : throw new BoardException("invalid id");

    [Function("me")]
    public Task<IActionResult> Me([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "me")] HttpRequest req) =>
        ep.RunAsync(req, me => Task.FromResult<object?>(me), role: null);

    [Function("channels")]
    public Task<IActionResult> Channels([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "channels")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await board.ListChannelsAsync(req.HttpContext.RequestAborted));

    [Function("participants")]
    public Task<IActionResult> Participants([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "participants")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await board.ListParticipantsAsync(req.HttpContext.RequestAborted));

    [Function("messages-list")]
    public Task<IActionResult> Messages([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "messages")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await board.ReadFeedAsync(new FeedQuery(
            Q(req, "channel"), Q(req, "incident"), Long(req, "after_seq"), Long(req, "before_seq"),
            Many(req, "type"), Q(req, "mentioning"),
            Q(req, "open_requests") == "true", Q(req, "roots_only") == "true", Int(req, "limit", 50)), req.HttpContext.RequestAborted));

    [Function("messages-post")]
    public Task<IActionResult> Post([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "messages")] HttpRequest req) =>
        ep.RunAsync(req, async me => await board.PostAsync(me, await Endpoint.BodyAsync<PostInput>(req), ct: req.HttpContext.RequestAborted));

    [Function("thread")]
    public Task<IActionResult> Thread([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "threads/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await board.GetThreadAsync(Id(id), req.HttpContext.RequestAborted));

    public sealed record ClaimBody(string Op, int? LeaseSeconds);

    [Function("claim")]
    public Task<IActionResult> Claim([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "claims/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<ClaimBody>(req);
            return b.Op == "claim"
                ? await board.ClaimAsync(me, Id(id), b.LeaseSeconds, req.HttpContext.RequestAborted)
                : await board.SettleClaimAsync(me, Id(id), b.Op, req.HttpContext.RequestAborted);
        });

    [Function("search")]
    public Task<IActionResult> SearchMessages([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "search")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await search.RunAsync(new SearchQuery(
            Q(req, "q"), Q(req, "channel"), Many(req, "type"), Q(req, "author"),
            Q(req, "author_kind"), Q(req, "incident"), Q(req, "claim_state"), Date(req, "from"), Date(req, "to"),
            Q(req, "sort") ?? "newest", Int(req, "limit", 50), Int(req, "offset", 0)), req.HttpContext.RequestAborted));

    [Function("incidents-list")]
    public Task<IActionResult> Incidents([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents")] HttpRequest req) =>
        ep.RunAsync(req, async _ =>
        {
            await using var cmd = db.Command("""
                select id, graph_id, display_name, severity, status, classification, alert_count, web_url,
                       (select count(*)::int from messages m where m.incident_id = incidents.id) as message_count
                from incidents order by coalesce(updated_at_src, first_seen_at) desc limit 100
                """);
            var list = new List<object>();
            await using var r = await cmd.ExecuteReaderAsync(req.HttpContext.RequestAborted);
            while (await r.ReadAsync())
                list.Add(new
                {
                    id = r.GetGuid(0), graph_id = r.GetString(1), display_name = r.GetString(2), severity = r.GetString(3), status = r.GetString(4),
                    classification = r.Get<string>("classification"), alert_count = r.GetInt32(6), web_url = r.Get<string>("web_url"), message_count = r.GetInt32(8),
                });
            return list;
        });

    [Function("incident-get")]
    public Task<IActionResult> Incident([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await enrich.GetIncidentAsync(id, req.HttpContext.RequestAborted));

    [Function("actions-list")]
    public Task<IActionResult> Actions([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "actions")] HttpRequest req) =>
        ep.RunAsync(req, async _ => Q(req, "catalog") == "true"
            ? Broker.CatalogInfo(policy)
            : await broker.ListAsync(Q(req, "status"), req.HttpContext.RequestAborted));

    [Function("actions-request")]
    public Task<IActionResult> RequestAction([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions")] HttpRequest req) =>
        ep.RunAsync(req, async me => await broker.RequestAsync(me, await Endpoint.BodyAsync<ActionRequest>(req), req.HttpContext.RequestAborted));

    /// <summary>What policy would decide for this request, without filing it (the "Request action" form's live preview).</summary>
    [Function("actions-preview")]
    public Task<IActionResult> PreviewAction([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions/preview")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            me.Require(Roles.Requester);
            return await broker.AssessAsync(await Endpoint.BodyAsync<PreviewRequest>(req), req.HttpContext.RequestAborted);
        });

    /// <summary>The effective policy in words. Everyone on the board sees modes and counts; only admins see protected values.</summary>
    [Function("policy-get")]
    public Task<IActionResult> GetPolicy([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "policy")] HttpRequest req) =>
        ep.RunAsync(req, me => Task.FromResult<object?>(PolicyReport.Build(policy, includeLists: me.Has(Roles.Admin))));

    /// <summary>"What would happen if…": the same evaluation as a real request, for any principal on the board. Nothing is written.</summary>
    [Function("policy-simulate")]
    public Task<IActionResult> SimulatePolicy([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "policy/simulate")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await broker.AssessAsync(await Endpoint.BodyAsync<PreviewRequest>(req), req.HttpContext.RequestAborted));

    [Function("action-get")]
    public Task<IActionResult> GetAction([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "actions/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await broker.GetAsync(Id(id), req.HttpContext.RequestAborted) ?? throw BoardException.NotFound("action"));

    public sealed record DecisionBody(string Decision, string? Note, string? Confirm = null);

    [Function("action-decide")]
    public Task<IActionResult> Decide([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<DecisionBody>(req);
            return await broker.DecideAsync(me, Id(id), b.Decision, b.Note, req.HttpContext.RequestAborted, b.Confirm);
        });

    [Function("reports")]
    public Task<IActionResult> Reports([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "reports")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            me.Require(Roles.Admin);
            var report = await reporting.BuildAsync(Date(req, "from"), Date(req, "to"), Q(req, "severity"), req.HttpContext.RequestAborted);
            if (Q(req, "format") != "csv") return report;
            req.HttpContext.Response.Headers.ContentDisposition = $"attachment; filename=\"blueboard-response-{DateTime.UtcNow:yyyy-MM-dd}.csv\"";
            return new ContentResult { Content = Reporting.Csv(report), ContentType = "text/csv; charset=utf-8", StatusCode = 200 };
        });

    [Function("healthz")]
    public async Task<IActionResult> Health([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "healthz")] HttpRequest req)
    {
        await using var cmd = db.Command("select 1");
        await cmd.ExecuteScalarAsync(req.HttpContext.RequestAborted);
        return new OkObjectResult(new { ok = true });
    }
}
