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
public sealed class BoardApi(Endpoint ep, BoardService board, Search search, Reporting reporting, Broker broker, Enrichment enrich, Db db,
    IncidentQueries incidents, PlaybookRunner playbookRunner, PlaybookSet playbooks)
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
            if (b.Op == "claim") return await board.ClaimAsync(me, Id(id), b.LeaseSeconds, req.HttpContext.RequestAborted);
            var settled = await board.SettleClaimAsync(me, Id(id), b.Op, req.HttpContext.RequestAborted);
            await playbookRunner.AfterSettleAsync(settled, req.HttpContext.RequestAborted);
            return settled;
        });

    [Function("search")]
    public Task<IActionResult> SearchMessages([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "search")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await search.RunAsync(new SearchQuery(
            Q(req, "q"), Q(req, "channel"), Many(req, "type"), Q(req, "author"),
            Q(req, "author_kind"), Q(req, "incident"), Q(req, "claim_state"), Date(req, "from"), Date(req, "to"),
            Q(req, "sort") ?? "newest", Int(req, "limit", 50), Int(req, "offset", 0)), req.HttpContext.RequestAborted));

    /// <summary>?view=queue: the Queue home page (open incidents with aggregates). Otherwise the most recent incidents.</summary>
    [Function("incidents-list")]
    public Task<IActionResult> Incidents([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents")] HttpRequest req) =>
        ep.RunAsync(req, async me => Q(req, "view") == "queue"
            ? await incidents.QueueAsync(me, Q(req, "include_resolved") == "true", req.HttpContext.RequestAborted)
            : await incidents.ListAsync(Int(req, "limit", 100), req.HttpContext.RequestAborted));

    /// <summary>Incident detail plus the summary panel, rolled up from stored messages and actions.</summary>
    [Function("incident-get")]
    public Task<IActionResult> Incident([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ =>
        {
            var inc = await enrich.GetIncidentAsync(id, req.HttpContext.RequestAborted);
            var summary = await incidents.SummaryAsync(Guid.Parse(inc["id"]!.GetValue<string>()), req.HttpContext.RequestAborted);
            inc["summary"] = System.Text.Json.JsonSerializer.SerializeToNode(summary, Json.Options);
            return inc;
        });

    /// <summary>Loaded playbooks and the files skipped at startup (for a setup page).</summary>
    [Function("playbooks")]
    public Task<IActionResult> PlaybookList([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "playbooks")] HttpRequest req) =>
        ep.RunAsync(req, _ => Task.FromResult<object?>(new
        {
            playbooks = playbooks.All.Select(p => new { p.Id, p.Title, p.File, p.Match, steps = p.Steps.Count }),
            problems = playbooks.Problems,
        }));

    [Function("actions-list")]
    public Task<IActionResult> Actions([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "actions")] HttpRequest req) =>
        ep.RunAsync(req, async _ => Q(req, "catalog") == "true"
            ? Broker.CatalogInfo()
            : await broker.ListAsync(Q(req, "status"), req.HttpContext.RequestAborted));

    [Function("actions-request")]
    public Task<IActionResult> RequestAction([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions")] HttpRequest req) =>
        ep.RunAsync(req, async me => await broker.RequestAsync(me, await Endpoint.BodyAsync<ActionRequest>(req), req.HttpContext.RequestAborted));

    [Function("action-get")]
    public Task<IActionResult> GetAction([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "actions/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await broker.GetAsync(Id(id), req.HttpContext.RequestAborted) ?? throw BoardException.NotFound("action"));

    public sealed record DecisionBody(string Decision, string? Note);

    [Function("action-decide")]
    public Task<IActionResult> Decide([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<DecisionBody>(req);
            return await broker.DecideAsync(me, Id(id), b.Decision, b.Note, req.HttpContext.RequestAborted);
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
