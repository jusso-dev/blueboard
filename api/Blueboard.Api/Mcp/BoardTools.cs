using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Extensions.Mcp;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api.Mcp;

/// <summary>
/// MCP tools for agents, served by the Azure Functions MCP extension at /runtime/webhooks/mcp
/// (Streamable HTTP). Every call authenticates the bearer token from the transport headers and
/// re-reads the caller's roles from Entra; there is no shared key. Board content is untrusted data.
/// </summary>
public sealed class BoardTools(Authenticator auth, BoardService board, Broker broker, Enrichment enrich, ILogger<BoardTools> log)
{
    /// <summary>Authenticate the MCP caller (bearer token), require a role, run, and return JSON text or an error string.</summary>
    private async Task<string> Call(ToolInvocationContext ctx, string? role, Func<Principal, Task<object?>> fn)
    {
        try
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (ctx.TryGetHttpTransport(out var http) && http is not null)
                foreach (var h in http.Headers) headers[h.Key.ToLowerInvariant()] = h.Value;
            var me = await auth.AuthenticateAsync(headers);
            if (role is not null && !me.Has(role)) return $"error: missing role {role} (ask an admin to assign Board.{RoleName(role)})";
            return Json.Serialize(await fn(me));
        }
        catch (BoardException ex)
        {
            return $"error: {ex.Message}";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "MCP tool {Tool} failed", ctx.Name);
            return "error: internal error";
        }
    }

    private static string RoleName(string role) => role switch
    {
        Roles.Poster => "Post", Roles.Hunter => "Hunt", Roles.Requester => "RequestActions", _ => role,
    };

    private static Guid Guid_(string s) => Guid.TryParse(s, out var g) ? g : throw new BoardException("invalid message id");

    [Function(nameof(WhoAmI))]
    public Task<string> WhoAmI([McpToolTrigger("whoami", "Your board identity, handle and roles.")] ToolInvocationContext ctx) =>
        Call(ctx, null, me => Task.FromResult<object?>(me));

    [Function(nameof(ListChannels))]
    public Task<string> ListChannels([McpToolTrigger("list_channels", "Channels on the board with their topics and latest seq.")] ToolInvocationContext ctx) =>
        Call(ctx, Roles.Poster, async _ => await board.ListChannelsAsync());

    [Function(nameof(ListParticipants))]
    public Task<string> ListParticipants([McpToolTrigger("list_participants", "Agents and people on the board (handles to @mention).")] ToolInvocationContext ctx) =>
        Call(ctx, Roles.Poster, async _ => await board.ListParticipantsAsync());

    [Function(nameof(ReadFeed))]
    public Task<string> ReadFeed(
        [McpToolTrigger("read_feed", "Read board messages. Pass after_seq (the cursor from your last call) to get only new messages, oldest first. Filter by channel, incident, types (comma-separated), mentioning, open_requests.")] ToolInvocationContext ctx,
        [McpToolProperty("channel", "Channel name, e.g. incidents")] string? channel,
        [McpToolProperty("incident", "Board incident id or Defender incident id")] string? incident,
        [McpToolProperty("after_seq", "Cursor: only messages with a higher seq")] string? afterSeq,
        [McpToolProperty("types", "Comma-separated message types")] string? types,
        [McpToolProperty("mentioning", "Only messages that @mention this handle")] string? mentioning,
        [McpToolProperty("open_requests", "Only claimable messages nobody holds")] bool? openRequests,
        [McpToolProperty("limit", "1-200, default 50")] int? limit) =>
        Call(ctx, Roles.Poster, async _ => await board.ReadFeedAsync(new FeedQuery(
            channel, incident, long.TryParse(afterSeq, out var a) ? a : null, null,
            types?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), mentioning,
            openRequests ?? false, false, limit ?? 50)));

    [Function(nameof(GetThread))]
    public Task<string> GetThread(
        [McpToolTrigger("get_thread", "A message and all its replies.")] ToolInvocationContext ctx,
        [McpToolProperty("message_id", "Thread root message id", isRequired: true)] string messageId) =>
        Call(ctx, Roles.Poster, async _ => await board.GetThreadAsync(Guid_(messageId)));

    [Function(nameof(PostMessage))]
    public Task<string> PostMessage(
        [McpToolTrigger("post_message", "Post to a channel. type: chat | finding | question | ioc | verdict | status. payload_json shapes: ioc {\"indicators\":[{\"kind\",\"value\",\"verdict\",\"source\"}]}, verdict {\"classification\",\"confidence\",\"determination\"}, finding {\"confidence\",\"entities\",\"evidence\"}, status {\"state\"}. Use parent_id to reply in a thread and incident to link it.")] ToolInvocationContext ctx,
        [McpToolProperty("channel", "Channel name", isRequired: true)] string channel,
        [McpToolProperty("body", "Markdown. @handle to mention someone.", isRequired: true)] string body,
        [McpToolProperty("type", "chat | finding | question | ioc | verdict | status")] string? type,
        [McpToolProperty("payload_json", "Typed payload as a JSON object string")] string? payloadJson,
        [McpToolProperty("parent_id", "Thread root message id")] string? parentId,
        [McpToolProperty("incident", "Board incident id or Defender incident id")] string? incident) =>
        Call(ctx, Roles.Poster, async me =>
        {
            JsonElement? payload = string.IsNullOrWhiteSpace(payloadJson) ? null : JsonDocument.Parse(payloadJson).RootElement.Clone();
            return await board.PostAsync(me, new PostInput(channel, body, type, payload, parentId is null ? null : Guid_(parentId), incident));
        });

    [Function(nameof(ClaimMessage))]
    public Task<string> ClaimMessage(
        [McpToolTrigger("claim_message", "Claim a question/finding/ioc so others know you are handling it. Fails if someone else holds it. Leases expire.")] ToolInvocationContext ctx,
        [McpToolProperty("message_id", "Message id", isRequired: true)] string messageId,
        [McpToolProperty("lease_seconds", "30-3600, default 600")] int? leaseSeconds) =>
        Call(ctx, Roles.Poster, async me => await board.ClaimAsync(me, Guid_(messageId), leaseSeconds));

    [Function(nameof(CompleteClaim))]
    public Task<string> CompleteClaim(
        [McpToolTrigger("complete_claim", "Finish (outcome=done) or hand back (outcome=release) a message you claimed.")] ToolInvocationContext ctx,
        [McpToolProperty("message_id", "Message id", isRequired: true)] string messageId,
        [McpToolProperty("outcome", "done | release", isRequired: true)] string outcome) =>
        Call(ctx, Roles.Poster, async me => await board.SettleClaimAsync(me, Guid_(messageId), outcome));

    [Function(nameof(GetIncident))]
    public Task<string> GetIncident(
        [McpToolTrigger("get_incident", "Incident details from Defender XDR / Sentinel as last synced: alerts, MITRE techniques, extracted entities.")] ToolInvocationContext ctx,
        [McpToolProperty("incident", "Board incident id or Defender incident id", isRequired: true)] string incident) =>
        Call(ctx, Roles.Poster, async _ => await enrich.GetIncidentAsync(incident));

    [Function(nameof(RunHuntingQuery))]
    public Task<string> RunHuntingQuery(
        [McpToolTrigger("run_hunting_query", "Run a read-only KQL advanced hunting query across Defender XDR and Sentinel tables. Max 200 rows returned. Needs Board.Hunt.")] ToolInvocationContext ctx,
        [McpToolProperty("query", "KQL query", isRequired: true)] string query,
        [McpToolProperty("timespan", "ISO-8601 duration, default P7D")] string? timespan) =>
        Call(ctx, Roles.Hunter, async me => await enrich.HuntAsync(me, query, timespan));

    [Function(nameof(LookupEntity))]
    public Task<string> LookupEntity(
        [McpToolTrigger("lookup_entity", "Read-only context for a user (UPN/id), device (MDE id or DNS name), ip, file (sha1/sha256) or url/domain. Needs Board.Hunt.")] ToolInvocationContext ctx,
        [McpToolProperty("kind", "user | device | ip | file | url", isRequired: true)] string kind,
        [McpToolProperty("value", "The entity", isRequired: true)] string value) =>
        Call(ctx, Roles.Hunter, async me => await enrich.LookupAsync(me, kind, value));

    [Function(nameof(ListActionTypes))]
    public Task<string> ListActionTypes([McpToolTrigger("list_action_types", "Containment / eradication actions the board can broker, with JSON schemas for params.")] ToolInvocationContext ctx) =>
        Call(ctx, Roles.Poster, _ => Task.FromResult<object?>(Broker.CatalogInfo()));

    [Function(nameof(RequestAction))]
    public Task<string> RequestAction(
        [McpToolTrigger("request_action", "Ask the board to perform a containment/eradication action. Policy runs first; destructive actions wait for a human approver. You'll see the outcome as an action_result message in #containment. Needs Board.RequestActions.")] ToolInvocationContext ctx,
        [McpToolProperty("kind", "Action kind from list_action_types", isRequired: true)] string kind,
        [McpToolProperty("params_json", "Action params as a JSON object string", isRequired: true)] string paramsJson,
        [McpToolProperty("justification", "Why, citing evidence on the board (20-4000 chars)", isRequired: true)] string justification,
        [McpToolProperty("incident", "Board incident id or Defender incident id")] string? incident,
        [McpToolProperty("parent_id", "Board message this responds to")] string? parentId) =>
        Call(ctx, Roles.Requester, async me => await broker.RequestAsync(me,
            new ActionRequest(kind, JsonDocument.Parse(paramsJson).RootElement.Clone(), justification, incident, parentId is null ? null : Guid_(parentId))));

    [Function(nameof(GetAction))]
    public Task<string> GetAction(
        [McpToolTrigger("get_action", "Status and result of a brokered action.")] ToolInvocationContext ctx,
        [McpToolProperty("action_id", "Action id", isRequired: true)] string actionId) =>
        Call(ctx, Roles.Poster, async _ => await broker.GetAsync(Guid_(actionId)) ?? throw BoardException.NotFound("action"));
}
