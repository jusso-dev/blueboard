using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Webhooks;
using Blueboard.Contracts;
using Blueboard.Api.Intel;
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
public sealed class BoardApi(Endpoint ep, BoardService board, Search search, Reporting reporting, Broker broker, Enrichment enrich, Ingest ingest, WebhookService hooks, Db db, Policy policy,
    IncidentQueries incidents, PlaybookRunner playbookRunner, PlaybookSet playbooks, IntelService intel, Audit audit, GifService gifs, MemoryService memory, AttackViews attack,
    PolicyStore? policyStore = null)
{
    /// <summary>policy.json ∩ admin overrides when the store is wired; policy.json alone otherwise.</summary>
    private async Task<Policy> EffectiveAsync(HttpRequest req) => policyStore is null ? policy : await policyStore.CurrentAsync(Ct(req));

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

    [Function("gifs-search")]
    [RouteDoc("Search allowlisted reaction GIFs (curated out of the box, or GIPHY/Tenor when configured)")]
    public Task<IActionResult> SearchGifs([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "gifs/search")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            var q = req.Query["q"].FirstOrDefault();
            int? limit = int.TryParse(req.Query["limit"].FirstOrDefault(), out var l) ? l : null;
            return await gifs.SearchAsync(me, q, limit, Ct(req));
        });

    // ── shared SOC memory (/memory) ────────────────────────────────────────────────────────────
    [Function("memories-list")]
    [RouteDoc("Search shared SOC memories (baselines, asset context, environment facts, procedures)", Query = typeof(MemoryQuery), Response = typeof(SharedMemory[]))]
    public Task<IActionResult> ListMemories([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "memories")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await memory.ListAsync(Endpoint.Query<MemoryQuery>(req), Ct(req)));

    [Function("memories-remember")]
    [RouteDoc("Create or update a shared SOC memory by key", Body = typeof(MemoryInput), Response = typeof(SharedMemory))]
    public Task<IActionResult> RememberMemory([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "memories")] HttpRequest req) =>
        ep.RunAsync(req, async me => await memory.RememberAsync(me, await Endpoint.BodyAsync<MemoryInput>(req), Ct(req)));

    [Function("memories-verify")]
    [RouteDoc("Human-only: verify, unverify, or pin a shared SOC memory", Body = typeof(MemoryVerifyInput), Response = typeof(SharedMemory))]
    public Task<IActionResult> VerifyMemory([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "memories/{id:guid}/verify")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await memory.SetVerificationAsync(me, Id(id), await Endpoint.BodyAsync<MemoryVerifyInput>(req), Ct(req)));

    [Function("memories-forget")]
    [RouteDoc("Archive an obsolete shared SOC memory")]
    public Task<IActionResult> ForgetMemory([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "memories/{id:guid}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await memory.ForgetAsync(me, Id(id), null, req.Query["reason"].FirstOrDefault(), Ct(req)));

    [Function("thread")]
    [RouteDoc("A thread root and its replies", Response = typeof(ThreadResult))]
    public Task<IActionResult> Thread([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "threads/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await board.GetThreadAsync(Id(id), Ct(req)));

    [Function("message-reactions")]
    [RouteDoc("Add or remove your emoji reaction on a message; returns the message's reactions", Body = typeof(ReactionOp), Response = typeof(Reaction[]))]
    public Task<IActionResult> React([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "messages/{id:guid}/reactions")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<ReactionOp>(req);
            return await board.ReactAsync(me, Id(id), b.Emoji, b.Op == "remove", Ct(req));
        });

    [Function("typing-set")]
    [RouteDoc("You are typing (in a thread, or a channel's or incident's composer). Lasts 6 seconds; send again while typing", Body = typeof(TypingInput))]
    public Task<IActionResult> Typing([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "typing")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            await board.TypingAsync(me, await Endpoint.BodyAsync<TypingInput>(req), Ct(req));
            return null;
        });

    [Function("typing-get")]
    [RouteDoc("Who is typing: thread=X in that thread; incident=Y anywhere on the incident; channel=C a top-level post in C. Excludes you", Query = typeof(TypingQuery), Response = typeof(Author[]))]
    public Task<IActionResult> WhoIsTyping([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "typing")] HttpRequest req) =>
        ep.RunAsync(req, async me => await board.WhoIsTypingAsync(me, Endpoint.Query<TypingQuery>(req), Ct(req)));

    [Function("claim")]
    [RouteDoc("Claim, finish or release a question/finding/ioc", Body = typeof(ClaimOp), Response = typeof(Message))]
    public Task<IActionResult> Claim([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "claims/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<ClaimOp>(req);
            if (b.Op == "claim") return await board.ClaimAsync(me, Id(id), b.LeaseSeconds, Ct(req));
            var settled = await board.SettleClaimAsync(me, Id(id), b.Op, Ct(req));
            await playbookRunner.AfterSettleAsync(settled, Ct(req));
            return settled;
        });

    [Function("search")]
    [RouteDoc("Full-text search with filters", Query = typeof(SearchQuery), Response = typeof(SearchResult))]
    public Task<IActionResult> SearchMessages([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "search")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await search.RunAsync(Endpoint.Query<SearchQuery>(req, TypeAlias), Ct(req)));

    /// <summary>?view=queue: the Queue home page (open incidents with aggregates). Otherwise the most recent incidents.</summary>
    [Function("incidents-list")]
    [RouteDoc("Incidents: view=queue for the home page queue, otherwise the latest", Query = typeof(IncidentsQuery))]
    public Task<IActionResult> Incidents([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            var q = Endpoint.Query<IncidentsQuery>(req);
            return q.View == "queue"
                ? await incidents.QueueAsync(me, q.IncludeResolved, Ct(req))
                : await incidents.ListAsync(q.Limit, Ct(req));
        });

    /// <summary>Incident detail plus the summary panel, rolled up from stored messages and actions.</summary>
    [Function("incident-get")]
    [RouteDoc("Incident detail: alerts, MITRE techniques, entities")]
    public Task<IActionResult> Incident([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ =>
        {
            var inc = await enrich.GetIncidentAsync(id, Ct(req));
            await intel.AnnotateIncidentAsync(inc, Ct(req));
            var summary = await incidents.SummaryAsync(Guid.Parse(inc["id"]!.GetValue<string>()), Ct(req));
            inc["summary"] = System.Text.Json.JsonSerializer.SerializeToNode(summary, Json.Options);
            return inc;
        });

    /// <summary>The incident's attack timeline: alerts, timestamped evidence, reported events, verdicts and actions, oldest first.</summary>
    [Function("incident-timeline")]
    [RouteDoc("Attack timeline: alerts, evidence, reported events, verdicts and actions, oldest first, each citing its source", Query = typeof(TimelineFilter), Response = typeof(IncidentTimelineResult))]
    public Task<IActionResult> Timeline([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents/{id}/timeline")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ =>
        {
            var q = Endpoint.Query<TimelineFilter>(req);
            return await attack.TimelineAsync(id, q.Entity, q.Source, q.Limit, Ct(req));
        });

    /// <summary>The incident's attack graph: entities and the relationships the evidence gives them. Protected entries are named for admins only.</summary>
    [Function("incident-graph")]
    [RouteDoc("Attack graph: entities, relationships, verdicts, protected flags and targeted actions", Response = typeof(IncidentGraphResult))]
    public Task<IActionResult> AttackGraph([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents/{id}/graph")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await attack.GraphAsync(me, id, Ct(req)));

    /// <summary>Loaded playbooks and the files skipped at startup (for a setup page).</summary>
    [Function("playbooks")]
    [RouteDoc("Loaded playbooks and the files skipped at startup")]
    public Task<IActionResult> PlaybookList([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "playbooks")] HttpRequest req) =>
        ep.RunAsync(req, _ => Task.FromResult<object?>(new
        {
            playbooks = playbooks.All.Select(p => new { p.Id, p.Title, p.File, p.Priority, p.Scope, p.Match, steps = p.Steps.Count }),
            problems = playbooks.Problems,
        }));

    /// <summary>Sync one Defender/Sentinel incident directly from Microsoft Graph by its numeric id (for Sentinel automation rules or on-demand refresh).</summary>
    [Function("incident-sync")]
    [RouteDoc("Fetch a Defender/Sentinel incident from Microsoft Graph by numeric id and upsert it")]
    public Task<IActionResult> IncidentSync([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "incidents/{id}/sync")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ =>
        {
            var (outcome, graphId) = await ingest.SyncOneAsync(id, Ct(req));
            return new { graph_id = graphId, outcome = outcome.ToString().ToLowerInvariant() };
        });

    public sealed record PlaybookAttachBody(string PlaybookId);

    /// <summary>Attach a playbook checklist to an incident that doesn't have one yet.</summary>
    [Function("incident-playbook-attach")]
    [RouteDoc("Attach a playbook checklist to an incident", Body = typeof(PlaybookAttachBody))]
    public Task<IActionResult> AttachPlaybook([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "incidents/{id}/playbook")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<PlaybookAttachBody>(req);
            return await playbookRunner.AttachByIdAsync(me, id, b.PlaybookId, Ct(req));
        });

    // ── threat intel (/intel pages) ────────────────────────────────────────────────────────────
    public sealed record WatchBody(string? Kind, string? Value, bool? Enabled, string? Label = null);

    [Function("intel-index")]
    [RouteDoc("Threat intel index: newest records, findings table, watches, source status")]
    public Task<IActionResult> IntelIndex([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "intel")] HttpRequest req) =>
        ep.RunAsync(req, async me => await intel.IndexAsync(me, Ct(req)));

    [Function("intel-lookup")]
    [RouteDoc("Intel for one key: a card per source")]
    public Task<IActionResult> IntelLookup([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "intel/lookup")] HttpRequest req) =>
        ep.RunAsync(req, async me => await intel.LookupAsync(me, Endpoint.Query<IntelLookupInput>(req).Key, Ct(req)));

    [Function("intel-post")]
    [RouteDoc("Post an intel summary to #intel")]
    public Task<IActionResult> IntelPost([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "intel/post")] HttpRequest req) =>
        ep.RunAsync(req, async me => await intel.PostSummaryAsync(me, (await Endpoint.BodyAsync<IntelLookupInput>(req)).Key, Ct(req)));

    [Function("intel-badges")]
    [RouteDoc("KEV and EPSS badges for CVE ids")]
    public Task<IActionResult> IntelBadges([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "intel/badges")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await intel.BadgesAsync(req.Query["cve"].OfType<string>().Where(v => v.Length > 0).ToArray(), Ct(req)));

    [Function("intel-pwnwatch-brief")]
    [RouteDoc("pwn.watch remediation brief (untrusted text)")]
    public Task<IActionResult> IntelBrief([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "intel/pwnwatch/{slug}")] HttpRequest req, string slug) =>
        ep.RunAsync(req, async _ => await intel.PwnBriefAsync(slug, Ct(req)));

    [Function("intel-exposure")]
    [RouteDoc("Defender exposure for CVE ids", Role = Roles.Hunter)]
    public Task<IActionResult> IntelExposure([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "intel/exposure")] HttpRequest req) =>
        ep.RunAsync(req, async me => await intel.ExposureAsync(me, (await Endpoint.BodyAsync<ExposureInput>(req)).CveIds ?? [], Ct(req)), Roles.Hunter);

    [Function("intel-watches-list")]
    [RouteDoc("List configured tech stack and threat intel watchlists")]
    public Task<IActionResult> WatchList([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "intel/watches")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await intel.ListWatchesAsync(enabledOnly: req.Query["enabled"] == "true", Ct(req)));

    [Function("intel-watch-add")]
    [RouteDoc("Add a tech stack item or threat intel watch", Body = typeof(WatchBody), Role = Roles.Hunter)]
    public Task<IActionResult> WatchAdd([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "intel/watches")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<WatchBody>(req);
            return await intel.AddWatchAsync(me, b.Kind ?? "", b.Value ?? "", b.Label, Ct(req));
        }, Roles.Hunter);

    [Function("intel-watch-set")]
    [RouteDoc("Turn a watch on or off", Body = typeof(WatchBody), Role = Roles.Hunter)]
    public Task<IActionResult> WatchSet([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "intel/watches/{id:guid}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<WatchBody>(req);
            return await intel.SetWatchAsync(me, Id(id), b.Enabled ?? throw new BoardException("enabled required"), Ct(req));
        }, Roles.Hunter);

    [Function("intel-watch-delete")]
    [RouteDoc("Delete a watch or tech stack item", Role = Roles.Hunter)]
    public Task<IActionResult> WatchDelete([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "intel/watches/{id:guid}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await intel.DeleteWatchAsync(me, Id(id), Ct(req)), Roles.Hunter);

    [Function("intel-findings-list")]
    [RouteDoc("List Threat Intel findings posted by bots and analysts", Query = typeof(TiFindingsQuery), Response = typeof(TiFinding[]))]
    public Task<IActionResult> IntelFindings([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "intel/findings")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await intel.ListFindingsAsync(Endpoint.Query<TiFindingsQuery>(req), Ct(req)));

    [Function("intel-findings-post")]
    [RouteDoc("Post a Threat Intel finding tied to the org's tech stack or watchlists", Body = typeof(TiFindingInput), Response = typeof(TiFinding))]
    public Task<IActionResult> IntelFindingPost([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "intel/findings")] HttpRequest req) =>
        ep.RunAsync(req, async me => await intel.PostFindingAsync(me, await Endpoint.BodyAsync<TiFindingInput>(req), Ct(req)));

    [Function("intel-finding-status")]
    [RouteDoc("Update triage status of a Threat Intel finding", Body = typeof(TiFindingStatusInput), Response = typeof(TiFinding))]
    public Task<IActionResult> IntelFindingStatus([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "intel/findings/{id:guid}/status")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await intel.UpdateFindingStatusAsync(me, Id(id), (await Endpoint.BodyAsync<TiFindingStatusInput>(req)).Status, Ct(req)));

    public sealed record TiPlaybookBody(string? PlaybookId = null);

    /// <summary>Run the emerging-threat playbook (or another intel playbook) for a threat intel finding: steps go in a #intel thread.</summary>
    [Function("intel-finding-playbook")]
    [RouteDoc("Run an intel playbook (default emerging-threat-detection) for a threat intel finding", Body = typeof(TiPlaybookBody), Response = typeof(TiPlaybookRun))]
    public Task<IActionResult> IntelFindingPlaybook([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "intel/findings/{id:guid}/playbook")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var b = req.ContentLength is > 0 ? await Endpoint.BodyAsync<TiPlaybookBody>(req) : new TiPlaybookBody();
            return await playbookRunner.StartForTiFindingAsync(me, Id(id), b.PlaybookId, Ct(req));
        });

    [Function("actions-list")]
    [RouteDoc("Brokered actions (or the catalogue with catalog=true)", Query = typeof(ActionsQuery), Response = typeof(ActionRow[]))]
    public Task<IActionResult> Actions([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "actions")] HttpRequest req) =>
        ep.RunAsync(req, async _ =>
        {
            var q = Endpoint.Query<ActionsQuery>(req);
            return q.Catalog ? Broker.CatalogInfo(await EffectiveAsync(req)) : await broker.ListAsync(q.Status, q.Incident, Ct(req));
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
            return await broker.AssessAsync(me, await Endpoint.BodyAsync<PreviewRequest>(req), req.HttpContext.RequestAborted);
        });

    /// <summary>The effective policy in words. Everyone on the board sees modes and counts; only admins see protected values.</summary>
    [Function("policy-get")]
    [RouteDoc("The effective policy in words (protected values for admins only)")]
    public Task<IActionResult> GetPolicy([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "policy")] HttpRequest req) =>
        ep.RunAsync(req, async me => PolicyReport.Build(await EffectiveAsync(req), includeLists: me.Has(Roles.Admin)));

    /// <summary>"What would happen if…": the same evaluation as a real request, for any principal on the board. Nothing is written.</summary>
    [Function("policy-simulate")]
    [RouteDoc("Policy simulator: the same evaluation as a real request; nothing is written", Body = typeof(PreviewRequest))]
    public Task<IActionResult> SimulatePolicy([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "policy/simulate")] HttpRequest req) =>
        ep.RunAsync(req, async me => await broker.AssessAsync(me, await Endpoint.BodyAsync<PreviewRequest>(req), req.HttpContext.RequestAborted));

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
            await audit.WriteAsync(me.Id, "report.exported", me.Handle, new { rows = report.Rows.Count, from = q.From, to = q.To, severity = q.Severity }, Ct(req));
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
