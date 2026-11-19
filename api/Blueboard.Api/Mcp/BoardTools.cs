using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Blueboard.Api.Webhooks;
using Blueboard.Contracts;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Extensions.Mcp;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api.Mcp;

/// <summary>
/// MCP tools for agents, served by the Azure Functions MCP extension at /runtime/webhooks/mcp (Streamable HTTP).
/// Each tool's name, description, role and input record live in <see cref="Tools"/>; Program.cs registers the
/// inputSchema from the record (see <see cref="McpSchemas"/>), and the same record reads and validates the arguments.
/// Every call authenticates the bearer token from the transport headers and re-reads the caller's roles from Entra;
/// there is no shared key. Board content is untrusted data.
/// </summary>
public sealed class BoardTools(Authenticator auth, BoardService board, Broker broker, Enrichment enrich, WebhookService hooks, ILogger<BoardTools> log)
{
    /// <summary>Authenticate, require the tool's role, read its input record, run, and return JSON text or an error string.</summary>
    private async Task<string> Call<TIn>(ToolInvocationContext ctx, Func<Principal, TIn, Task<object?>> fn) where TIn : class
    {
        var tool = Tools.Get(ctx.Name);
        try
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (ctx.TryGetHttpTransport(out var http) && http is not null)
                foreach (var h in http.Headers) headers[h.Key.ToLowerInvariant()] = h.Value;
            var me = await auth.AuthenticateAsync(headers);
            if (tool.Role is { } role && !me.Has(role)) return $"error: missing role {role} (ask an admin to assign Board.{RoleName(role)}) (status 403)";
            var input = Contract.Read<TIn>(McpSchemas.Arguments(ctx.Arguments));
            return Json.Serialize(await fn(me, input));
        }
        catch (BoardException ex)
        {
            return $"error: {ex.Message} (status {ex.Status})";
        }
        catch (ContractException ex)
        {
            return $"error: {ex.Message} (status 400)";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "MCP tool {Tool} failed", ctx.Name);
            return "error: internal error (status 500)";
        }
    }

    private Task<string> Call(ToolInvocationContext ctx, Func<Principal, Task<object?>> fn) => Call<NoInput>(ctx, (me, _) => fn(me));

    private static string RoleName(string role) => role switch
    {
        Roles.Poster => "Post", Roles.Hunter => "Hunt", Roles.Requester => "RequestActions", _ => role,
    };

    [Function(nameof(WhoAmI))]
    public Task<string> WhoAmI([McpToolTrigger(Tools.WhoAmI, Tools.WhoAmIDoc)] ToolInvocationContext ctx) =>
        Call(ctx, me => Task.FromResult<object?>(me));

    [Function(nameof(ListChannels))]
    public Task<string> ListChannels([McpToolTrigger(Tools.ListChannels, Tools.ListChannelsDoc)] ToolInvocationContext ctx) =>
        Call(ctx, async _ => await board.ListChannelsAsync());

    [Function(nameof(ListParticipants))]
    public Task<string> ListParticipants([McpToolTrigger(Tools.ListParticipants, Tools.ListParticipantsDoc)] ToolInvocationContext ctx) =>
        Call(ctx, async _ => await board.ListParticipantsAsync());

    [Function(nameof(ReadFeed))]
    public Task<string> ReadFeed([McpToolTrigger(Tools.ReadFeed, Tools.ReadFeedDoc)] ToolInvocationContext ctx) =>
        Call<FeedQuery>(ctx, async (_, q) => await board.ReadFeedAsync(q));

    [Function(nameof(GetThread))]
    public Task<string> GetThread([McpToolTrigger(Tools.GetThread, Tools.GetThreadDoc)] ToolInvocationContext ctx) =>
        Call<ThreadQuery>(ctx, async (_, q) => await board.GetThreadAsync(q.MessageId));

    [Function(nameof(PostMessage))]
    public Task<string> PostMessage([McpToolTrigger(Tools.PostMessage, Tools.PostMessageDoc)] ToolInvocationContext ctx) =>
        Call<PostInput>(ctx, async (me, input) => await board.PostAsync(me, input));

    [Function(nameof(ClaimMessage))]
    public Task<string> ClaimMessage([McpToolTrigger(Tools.ClaimMessage, Tools.ClaimMessageDoc)] ToolInvocationContext ctx) =>
        Call<ClaimInput>(ctx, async (me, c) => await board.ClaimAsync(me, c.MessageId, c.LeaseSeconds));

    [Function(nameof(RenewClaim))]
    public Task<string> RenewClaim([McpToolTrigger(Tools.RenewClaim, Tools.RenewClaimDoc)] ToolInvocationContext ctx) =>
        Call<ClaimInput>(ctx, async (me, c) => await board.RenewClaimAsync(me, c.MessageId, c.LeaseSeconds));

    [Function(nameof(CompleteClaim))]
    public Task<string> CompleteClaim([McpToolTrigger(Tools.CompleteClaim, Tools.CompleteClaimDoc)] ToolInvocationContext ctx) =>
        Call<CompleteClaimInput>(ctx, async (me, c) => await board.SettleClaimAsync(me, c.MessageId, c.Outcome));

    [Function(nameof(GetIncident))]
    public Task<string> GetIncident([McpToolTrigger(Tools.GetIncident, Tools.GetIncidentDoc)] ToolInvocationContext ctx) =>
        Call<IncidentQuery>(ctx, async (_, q) => await enrich.GetIncidentAsync(q.Incident));

    [Function(nameof(RunHuntingQuery))]
    public Task<string> RunHuntingQuery([McpToolTrigger(Tools.RunHuntingQuery, Tools.RunHuntingQueryDoc)] ToolInvocationContext ctx) =>
        Call<HuntInput>(ctx, async (me, h) => await enrich.HuntAsync(me, h.Query, h.Timespan));

    [Function(nameof(LookupEntity))]
    public Task<string> LookupEntity([McpToolTrigger(Tools.LookupEntity, Tools.LookupEntityDoc)] ToolInvocationContext ctx) =>
        Call<LookupInput>(ctx, async (me, l) => await enrich.LookupAsync(me, l.Kind, l.Value));

    [Function(nameof(ListActionTypes))]
    public Task<string> ListActionTypes([McpToolTrigger(Tools.ListActionTypes, Tools.ListActionTypesDoc)] ToolInvocationContext ctx) =>
        Call(ctx, _ => Task.FromResult<object?>(Broker.CatalogInfo()));

    [Function(nameof(RequestAction))]
    public Task<string> RequestAction([McpToolTrigger(Tools.RequestAction, Tools.RequestActionDoc)] ToolInvocationContext ctx) =>
        Call<ActionRequest>(ctx, async (me, r) => await broker.RequestAsync(me, r));

    [Function(nameof(GetAction))]
    public Task<string> GetAction([McpToolTrigger(Tools.GetAction, Tools.GetActionDoc)] ToolInvocationContext ctx) =>
        Call<ActionQuery>(ctx, async (_, q) => await broker.GetAsync(q.ActionId) ?? throw BoardException.NotFound("action"));

    [Function(nameof(Subscribe))]
    public Task<string> Subscribe([McpToolTrigger(Tools.Subscribe, Tools.SubscribeDoc)] ToolInvocationContext ctx) =>
        Call<SubscribeInput>(ctx, async (me, s) => await hooks.SubscribeAsync(me, s));

    [Function(nameof(Unsubscribe))]
    public Task<string> Unsubscribe([McpToolTrigger(Tools.Unsubscribe, Tools.UnsubscribeDoc)] ToolInvocationContext ctx) =>
        Call<UnsubscribeInput>(ctx, async (me, u) => await hooks.UnsubscribeAsync(me, u.SubscriptionId));

    [Function(nameof(ScheduleFollowup))]
    public Task<string> ScheduleFollowup([McpToolTrigger(Tools.ScheduleFollowup, Tools.ScheduleFollowupDoc)] ToolInvocationContext ctx) =>
        Call<FollowupInput>(ctx, async (me, f) => await hooks.ScheduleFollowupAsync(me, f));
}
