using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Webhooks;
using Blueboard.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Blueboard.Api.Http;

/// <summary>
/// REST API for the React app, called cross-origin from the web app with an Entra bearer token (CORS allows only the web origin).
/// Every route needs Board.Post (Board.Admin for reports), except /me which tells a role-less user why.
/// Inputs are the contract records in Blueboard.Contracts (the same ones the MCP tools use), and each route's
/// [RouteDoc] feeds /api/openapi.json.
/// </summary>
public sealed class BoardApi(Endpoint ep, BoardService board, Search search, Reporting reporting, Broker broker, Enrichment enrich, WebhookService hooks, Db db, Policy policy)
{
    /// <summary>The web app sends ?type=a&amp;type=b; the contract field is types.</summary>
    private static readonly Dictionary<string, string> TypeAlias = new() { ["type"] = "types" };
    private static Guid Id(string s) => Guid.TryParse(s, out var g) ? g : throw new BoardException("invalid id");
    private static CancellationToken Ct(HttpRequest r) => r.HttpContext.RequestAborted;

    [Function("me")]
    [RouteDoc("The caller's board identity and roles", Response = typeof(Identity), Role = null)]
    public Task<IActionResult> Me([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "me")] HttpRequest req) =>
        ep.RunAsync(req, me => Task.FromResult<object?>(me), role: null);

    [Function("channels")]
    [RouteDoc("Channels with topics and latest seq", Response = typeof(ChannelInfo[]))]
    public Task<IActionResult> Channels([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "channels")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await board.ListChannelsAsync(Ct(req)));

    [Function("participants")]
    [RouteDoc("Agents and people on the board", Response = typeof(Participant[]))]
    public Task<IActionResult> Participants([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "participants")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await board.ListParticipantsAsync(Ct(req)));

    [Function("messages-list")]
    [RouteDoc("Read the feed (cursor after_seq, filters)", Query = typeof(FeedQuery), Response = typeof(FeedResult))]
    public Task<IActionResult> Messages([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "messages")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await board.ReadFeedAsync(Endpoint.Query<FeedQuery>(req, TypeAlias), Ct(req)));

    [Function("messages-post")]
    [RouteDoc("Post a message", Body = typeof(PostInput), Response = typeof(Message))]
    public Task<IActionResult> Post([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "messages")] HttpRequest req) =>
        ep.RunAsync(req, async me => await board.PostAsync(me, await Endpoint.BodyAsync<PostInput>(req), ct: Ct(req)));

    [Function("thread")]
    [RouteDoc("A thread root and its replies", Response = typeof(ThreadResult))]
    public Task<IActionResult> Thread([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "threads/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await board.GetThreadAsync(Id(id), Ct(req)));

    [Function("claim")]
    [RouteDoc("Claim, finish or release a question/finding/ioc", Body = typeof(ClaimOp), Response = typeof(Message))]
    public Task<IActionResult> Claim([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "claims/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<ClaimOp>(req);
            return b.Op == "claim"
                ? await board.ClaimAsync(me, Id(id), b.LeaseSeconds, Ct(req))
                : await board.SettleClaimAsync(me, Id(id), b.Op, Ct(req));
        });

    [Function("search")]
    [RouteDoc("Full-text search with filters", Query = typeof(SearchQuery), Response = typeof(SearchResult))]
    public Task<IActionResult> SearchMessages([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "search")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await search.RunAsync(Endpoint.Query<SearchQuery>(req, TypeAlias), Ct(req)));

    [Function("incidents-list")]
    [RouteDoc("Latest 100 incidents")]
    public Task<IActionResult> Incidents([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents")] HttpRequest req) =>
        ep.RunAsync(req, async _ =>
        {
            await using var cmd = db.Command("""
                select id, graph_id, display_name, severity, status, classification, alert_count, web_url,
                       (select count(*)::int from messages m where m.incident_id = incidents.id) as message_count
                from incidents order by coalesce(updated_at_src, first_seen_at) desc limit 100
                """);
            var list = new List<object>();
            await using var r = await cmd.ExecuteReaderAsync(Ct(req));
            while (await r.ReadAsync())
                list.Add(new
                {
                    id = r.GetGuid(0), graph_id = r.GetString(1), display_name = r.GetString(2), severity = r.GetString(3), status = r.GetString(4),
                    classification = r.Get<string>("classification"), alert_count = r.GetInt32(6), web_url = r.Get<string>("web_url"), message_count = r.GetInt32(8),
                });
            return list;
        });

    [Function("incident-get")]
    [RouteDoc("Incident detail: alerts, MITRE techniques, entities")]
    public Task<IActionResult> Incident([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await enrich.GetIncidentAsync(id, Ct(req)));

    [Function("actions-list")]
    [RouteDoc("Brokered actions (or the catalogue with catalog=true)", Query = typeof(ActionsQuery), Response = typeof(ActionRow[]))]
    public Task<IActionResult> Actions([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "actions")] HttpRequest req) =>
        ep.RunAsync(req, async _ =>
        {
            var q = Endpoint.Query<ActionsQuery>(req);
            return q.Catalog ? Broker.CatalogInfo(policy) : await broker.ListAsync(q.Status, Ct(req));
        });

    [Function("actions-request")]
    [RouteDoc("Request a containment/eradication action", Body = typeof(ActionRequest), Response = typeof(ActionRow), Role = Roles.Requester)]
    public Task<IActionResult> RequestAction([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions")] HttpRequest req) =>
        ep.RunAsync(req, async me => await broker.RequestAsync(me, await Endpoint.BodyAsync<ActionRequest>(req), Ct(req)));

    /// <summary>What policy would decide for this request, without filing it (the "Request action" form's live preview).</summary>
    [Function("actions-preview")]
    [RouteDoc("What policy would decide for a request, without filing it", Body = typeof(PreviewRequest), Role = Roles.Requester)]
    public Task<IActionResult> PreviewAction([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions/preview")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            me.Require(Roles.Requester);
            return await broker.AssessAsync(await Endpoint.BodyAsync<PreviewRequest>(req), req.HttpContext.RequestAborted);
        });

    /// <summary>The effective policy in words. Everyone on the board sees modes and counts; only admins see protected values.</summary>
    [Function("policy-get")]
    [RouteDoc("The effective policy in words (protected values for admins only)")]
    public Task<IActionResult> GetPolicy([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "policy")] HttpRequest req) =>
        ep.RunAsync(req, me => Task.FromResult<object?>(PolicyReport.Build(policy, includeLists: me.Has(Roles.Admin))));

    /// <summary>"What would happen if…": the same evaluation as a real request, for any principal on the board. Nothing is written.</summary>
    [Function("policy-simulate")]
    [RouteDoc("Policy simulator: the same evaluation as a real request; nothing is written", Body = typeof(PreviewRequest))]
    public Task<IActionResult> SimulatePolicy([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "policy/simulate")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await broker.AssessAsync(await Endpoint.BodyAsync<PreviewRequest>(req), req.HttpContext.RequestAborted));

    [Function("action-get")]
    [RouteDoc("One action", Response = typeof(ActionRow))]
    public Task<IActionResult> GetAction([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "actions/{id:guid}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await broker.GetAsync(Id(id), Ct(req)) ?? throw BoardException.NotFound("action"));

    [Function("action-decide")]
    [RouteDoc("Approve or deny (human approvers only, never your own request)", Body = typeof(DecisionInput), Response = typeof(ActionRow), Role = Roles.Approver)]
    public Task<IActionResult> Decide([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions/{id:guid}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<DecisionInput>(req);
            return await broker.DecideAsync(me, Id(id), b.Decision, b.Note, Ct(req), b.Confirm);
        });

    [Function("subscriptions")]
    [RouteDoc("Webhook subscriptions (admin): all agents' subscriptions and their delivery health", Response = typeof(Subscription[]), Role = Roles.Admin)]
    public Task<IActionResult> Subscriptions([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "subscriptions")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await hooks.ListAllAsync(Ct(req)), role: Roles.Admin);

    [Function("reports")]
    [RouteDoc("Response metrics (admin); format=csv to download", Query = typeof(ReportQuery), Response = typeof(Report), Role = Roles.Admin)]
    public Task<IActionResult> Reports([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "reports")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            me.Require(Roles.Admin);
            var q = Endpoint.Query<ReportQuery>(req);
            var report = await reporting.BuildAsync(q.From, q.To, q.Severity, Ct(req));
            if (q.Format != "csv") return report;
            req.HttpContext.Response.Headers.ContentDisposition = $"attachment; filename=\"blueboard-response-{DateTime.UtcNow:yyyy-MM-dd}.csv\"";
            return new ContentResult { Content = Reporting.Csv(report), ContentType = "text/csv; charset=utf-8", StatusCode = 200 };
        });

    [Function("openapi")]
    [RouteDoc("This document (OpenAPI 3.1)", Role = "public")]
    public IActionResult OpenApiDocument([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "openapi.json")] HttpRequest req) =>
        new ContentResult { Content = OpenApi.Document().ToJsonString(), ContentType = "application/json", StatusCode = 200 };

    [Function("healthz")]
    [RouteDoc("Liveness and database check", Role = "public")]
    public async Task<IActionResult> Health([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "healthz")] HttpRequest req)
    {
        await using var cmd = db.Command("select 1");
        await cmd.ExecuteScalarAsync(Ct(req));
        return new OkObjectResult(new { ok = true });
    }
}
