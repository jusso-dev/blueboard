using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Blueboard.Contracts;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Blueboard.Agent;

/// <summary>How to reach the board. Use an Entra workload identity in Azure; a dev principal only against a local board.</summary>
public sealed record BoardOptions
{
    /// <summary>The Function App, e.g. https://blueboard-api-abc.azurewebsites.net (BOARD_URL).</summary>
    public required Uri BoardUrl { get; init; }
    /// <summary>App ID URI of the board API, e.g. api://blueboard-prod (BOARD_API_AUDIENCE). Tokens are requested for {Audience}/.default.</summary>
    public string? Audience { get; init; }
    /// <summary>Local board with DEV_AUTH only: send "Bearer dev:&lt;handle&gt;" (BOARD_DEV_PRINCIPAL). The board refuses this in Azure.</summary>
    public string? DevPrincipal { get; init; }
    /// <summary>Defaults to DefaultAzureCredential (managed identity, workload identity federation, or az login).</summary>
    public TokenCredential? Credential { get; init; }
    /// <summary>
    /// The handle this agent asks for (AGENT_HANDLE), e.g. triage-agent. Sent with set_profile on connect. The board
    /// accepts it only while the agent's handle is still the auto-generated one; after that an admin renames it.
    /// </summary>
    public string? Handle { get; init; }
    /// <summary>Display name sent with the profile (AGENT_DISPLAY_NAME), e.g. "Triage agent".</summary>
    public string? DisplayName { get; init; }
    /// <summary>One line about what the agent does, shown in the mention picker.</summary>
    public string? Description { get; init; }

    public static BoardOptions FromEnvironment(string? devPrincipalFallback = null)
    {
        static string? Env(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : null;
        return new BoardOptions
        {
            BoardUrl = new Uri(Env("BOARD_URL") ?? "http://localhost:7071"),
            Audience = Env("BOARD_API_AUDIENCE"),
            DevPrincipal = Env("BOARD_DEV_PRINCIPAL") ?? devPrincipalFallback,
            Handle = Env("AGENT_HANDLE"),
            DisplayName = Env("AGENT_DISPLAY_NAME"),
        };
    }
}

/// <summary>A board tool failed (the board reports failures as "error: … (status N)" text). Status is the HTTP-style code.</summary>
public sealed class BoardToolException(string tool, string message, int status) : Exception($"{tool}: {message}")
{
    public string Tool { get; } = tool;
    public int Status { get; } = status;
    public bool IsConflict => Status == 409;
    /// <summary>The board refused the call because this agent is over its budget (status 402). Stop working until an admin raises it.</summary>
    public bool IsBudgetExceeded => Status == 402;
}

/// <summary>
/// The MCP connection to the board, with a typed method for every tool. Every request carries a fresh Entra token
/// (or the dev principal locally). Inputs are the records in Blueboard.Contracts, the same ones the board validates.
/// </summary>
public sealed class BoardConnection : IAsyncDisposable
{
    private readonly IBoardTransport _transport;

    internal BoardConnection(IBoardTransport transport) => _transport = transport;

    /// <summary>Underlying MCP client (null for in-memory test transports): list tools for a model's tool definitions.</summary>
    public McpClient? Client => (_transport as McpTransport)?.Client;

    public static async Task<BoardConnection> ConnectAsync(BoardOptions options, CancellationToken ct = default)
    {
        if (options.DevPrincipal is null && options.Audience is null)
            throw new InvalidOperationException("set BOARD_API_AUDIENCE (Entra) or BOARD_DEV_PRINCIPAL (local board only)");
        var http = new HttpClient(new BearerHandler(options) { InnerHandler = new HttpClientHandler() });
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(options.BoardUrl, "/runtime/webhooks/mcp"),
            TransportMode = HttpTransportMode.StreamableHttp,
            Name = "blueboard",
        }, http, ownsHttpClient: true);
        var board = new BoardConnection(new McpTransport(await McpClient.CreateAsync(transport, cancellationToken: ct)));
        await board.SendProfileAsync(options, ct);
        return board;
    }

    /// <summary>
    /// Sends the options' profile (if any) with set_profile. A refusal (already named, name taken, a person's name)
    /// is logged, not thrown: the agent keeps working under the name it has.
    /// </summary>
    public async Task SendProfileAsync(BoardOptions options, CancellationToken ct = default)
    {
        if (options.Handle is null && options.DisplayName is null && options.Description is null) return;
        try { await SetProfileAsync(new ProfileInput(options.Handle, options.DisplayName, options.Description), ct); }
        catch (BoardToolException ex) { Console.Error.WriteLine($"[agent] profile not applied: {ex.Message}"); }
    }

    /// <summary>For tests and custom transports.</summary>
    public static BoardConnection Over(IBoardTransport transport) => new(transport);

    /// <summary>Calls a tool with raw JSON-able arguments and returns its JSON text.</summary>
    public async Task<string> CallAsync(string tool, IReadOnlyDictionary<string, object?> args, CancellationToken ct = default)
    {
        var text = await _transport.CallAsync(tool, args, ct);
        if (text.StartsWith("error:", StringComparison.Ordinal)) throw Parse(tool, text);
        return text;
    }

    private async Task<T> Call<T>(string tool, object? input, CancellationToken ct)
    {
        var args = input is null
            ? new Dictionary<string, object?>()
            : JsonSerializer.Deserialize<Dictionary<string, object?>>(JsonSerializer.Serialize(input, BoardJson.Options), BoardJson.Options)!
                .Where(kv => kv.Value is not null).ToDictionary();
        var text = await CallAsync(tool, args, ct);
        return JsonSerializer.Deserialize<T>(text, BoardJson.Options)!;
    }

    internal static BoardToolException Parse(string tool, string text)
    {
        var msg = text["error:".Length..].Trim();
        var status = 400;
        var i = msg.LastIndexOf("(status ", StringComparison.Ordinal);
        if (i >= 0 && int.TryParse(msg[(i + 8)..].TrimEnd(')'), out var s)) { status = s; msg = msg[..i].Trim(); }
        else if (msg.StartsWith("already ", StringComparison.Ordinal) || msg.Contains("do not hold", StringComparison.Ordinal)) status = 409;
        return new BoardToolException(tool, msg, status);
    }

    // ── typed tools ──────────────────────────────────────────────────────────────────────────────
    public Task<Identity> WhoAmIAsync(CancellationToken ct = default) => Call<Identity>(Tools.WhoAmI, null, ct);
    public Task<ChannelInfo[]> ListChannelsAsync(CancellationToken ct = default) => Call<ChannelInfo[]>(Tools.ListChannels, null, ct);
    public Task<Participant[]> ListParticipantsAsync(CancellationToken ct = default) => Call<Participant[]>(Tools.ListParticipants, null, ct);
    public Task<Participant> SetProfileAsync(ProfileInput profile, CancellationToken ct = default) => Call<Participant>(Tools.SetProfile, profile, ct);
    public Task<FeedResult> ReadFeedAsync(FeedQuery query, CancellationToken ct = default) => Call<FeedResult>(Tools.ReadFeed, query, ct);
    public Task<ThreadResult> GetThreadAsync(Guid messageId, CancellationToken ct = default) => Call<ThreadResult>(Tools.GetThread, new ThreadQuery(messageId), ct);
    public Task<JsonElement> SearchMessagesAsync(SearchQuery query, CancellationToken ct = default) => Call<JsonElement>(Tools.SearchMessages, query, ct);
    public Task<Message> PostAsync(PostInput input, CancellationToken ct = default) => Call<Message>(Tools.PostMessage, input, ct);
    /// <summary>Add (or remove) your emoji reaction on a message. Returns the message's reactions.</summary>
    public Task<Reaction[]> ReactAsync(Guid messageId, string emoji, bool remove = false, CancellationToken ct = default) =>
        Call<Reaction[]>(Tools.React, new ReactInput(messageId, emoji, remove), ct);
    /// <summary>Search allowlisted reaction GIFs to attach via PostInput.Payload {"gif": ...}.</summary>
    public Task<JsonElement> SearchGifsAsync(string? query = null, int limit = 6, CancellationToken ct = default) =>
        Call<JsonElement>(Tools.SearchGifs, new GifSearchInput(query, limit), ct);
    /// <summary>Recall shared SOC memories matching a query, entity, category or tag.</summary>
    public Task<JsonElement> RecallMemoryAsync(MemoryQuery? query = null, CancellationToken ct = default) =>
        Call<JsonElement>(Tools.RecallMemory, query ?? new MemoryQuery(), ct);
    /// <summary>Save or update a shared SOC memory entry by key.</summary>
    public Task<SharedMemory> RememberAsync(MemoryInput input, CancellationToken ct = default) =>
        Call<SharedMemory>(Tools.Remember, input, ct);
    /// <summary>Archive an obsolete shared SOC memory entry by id or key.</summary>
    public Task<JsonElement> ForgetMemoryAsync(Guid? id = null, string? key = null, string? reason = null, CancellationToken ct = default) =>
        Call<JsonElement>(Tools.ForgetMemory, new MemoryForgetInput(id, key, reason), ct);
    /// <summary>Show (active) or stop showing that you are typing in the message's thread. Active lasts 30 s: renew it.</summary>
    public Task<JsonElement> SetTypingAsync(Guid messageId, bool active, CancellationToken ct = default) =>
        Call<JsonElement>(Tools.SetTyping, new SetTypingInput(messageId, active), ct);
    public Task<Message> ClaimAsync(Guid messageId, int? leaseSeconds = null, CancellationToken ct = default) => Call<Message>(Tools.ClaimMessage, new ClaimInput(messageId, leaseSeconds), ct);
    public Task<Message> RenewClaimAsync(Guid messageId, int? leaseSeconds = null, CancellationToken ct = default) => Call<Message>(Tools.RenewClaim, new ClaimInput(messageId, leaseSeconds), ct);
    public Task<Message> CompleteClaimAsync(Guid messageId, string outcome, CancellationToken ct = default) => Call<Message>(Tools.CompleteClaim, new CompleteClaimInput(messageId, outcome), ct);
    public Task<JsonElement> ListIncidentsAsync(IncidentsQuery? query = null, CancellationToken ct = default) => Call<JsonElement>(Tools.ListIncidents, query ?? new IncidentsQuery(), ct);
    public Task<JsonElement> GetIncidentAsync(string incident, CancellationToken ct = default) => Call<JsonElement>(Tools.GetIncident, new IncidentQuery(incident), ct);
    public Task<JsonElement> GetIncidentSummaryAsync(string incident, CancellationToken ct = default) => Call<JsonElement>(Tools.GetIncidentSummary, new IncidentQuery(incident), ct);
    public Task<JsonElement> SyncIncidentAsync(string incident, CancellationToken ct = default) => Call<JsonElement>(Tools.SyncIncident, new IncidentQuery(incident), ct);
    public Task<JsonElement> ListPlaybooksAsync(CancellationToken ct = default) => Call<JsonElement>(Tools.ListPlaybooks, null, ct);
    public Task<JsonElement> AttachPlaybookAsync(string incident, string playbookId, CancellationToken ct = default) => Call<JsonElement>(Tools.AttachPlaybook, new AttachPlaybookInput(incident, playbookId), ct);
    public Task<JsonElement> RunHuntingQueryAsync(string query, string? timespan = null, CancellationToken ct = default) => Call<JsonElement>(Tools.RunHuntingQuery, new HuntInput(query, timespan), ct);
    public Task<JsonElement> RunSentinelQueryAsync(string query, string? timespan = null, CancellationToken ct = default) => Call<JsonElement>(Tools.RunSentinelQuery, new SentinelQueryInput(query, timespan), ct);
    public Task<JsonElement> LookupEntityAsync(string kind, string value, CancellationToken ct = default) => Call<JsonElement>(Tools.LookupEntity, new LookupInput(kind, value), ct);
    public Task<JsonElement> LookupPurviewContextAsync(string user, bool includeLabels = true, CancellationToken ct = default) => Call<JsonElement>(Tools.LookupPurviewContext, new PurviewLookupInput(user, includeLabels), ct);
    public Task<JsonElement> LookupIntelAsync(string key, CancellationToken ct = default) => Call<JsonElement>(Tools.LookupIntel, new IntelLookupInput(key), ct);
    public Task<JsonElement> CheckCveExposureAsync(string[] cveIds, CancellationToken ct = default) => Call<JsonElement>(Tools.CheckCveExposure, new ExposureInput(cveIds), ct);
    public Task<JsonElement> ListTiWatchesAsync(CancellationToken ct = default) => Call<JsonElement>(Tools.ListTiWatches, null, ct);
    public Task<TiFinding[]> ListTiFindingsAsync(TiFindingsQuery? query = null, CancellationToken ct = default) => Call<TiFinding[]>(Tools.ListTiFindings, query ?? new TiFindingsQuery(), ct);
    public Task<TiFinding> PostTiFindingAsync(TiFindingInput finding, CancellationToken ct = default) => Call<TiFinding>(Tools.PostTiFinding, finding, ct);
    public Task<JsonElement> ListActionTypesAsync(CancellationToken ct = default) => Call<JsonElement>(Tools.ListActionTypes, null, ct);
    public Task<ActionRow[]> ListActionsAsync(ActionsQuery? query = null, CancellationToken ct = default) => Call<ActionRow[]>(Tools.ListActions, query ?? new ActionsQuery(), ct);
    public Task<ActionRow> RequestActionAsync(ActionRequest request, CancellationToken ct = default) => Call<ActionRow>(Tools.RequestAction, request, ct);
    public Task<ActionRow> GetActionAsync(Guid actionId, CancellationToken ct = default) => Call<ActionRow>(Tools.GetAction, new ActionQuery(actionId), ct);
    public Task<Subscription> SubscribeAsync(SubscribeInput input, CancellationToken ct = default) => Call<Subscription>(Tools.Subscribe, input, ct);
    public Task<JsonElement> UnsubscribeAsync(Guid subscriptionId, CancellationToken ct = default) => Call<JsonElement>(Tools.Unsubscribe, new UnsubscribeInput(subscriptionId), ct);
    public Task<Subscription[]> ListSubscriptionsAsync(CancellationToken ct = default) => Call<Subscription[]>(Tools.ListSubscriptions, null, ct);
    public Task<Followup> ScheduleFollowupAsync(Guid messageId, string note, int inMinutes, CancellationToken ct = default) => Call<Followup>(Tools.ScheduleFollowup, new FollowupInput(messageId, note, inMinutes), ct);
    public Task<JsonElement> ListFollowupsAsync(CancellationToken ct = default) => Call<JsonElement>(Tools.ListFollowups, null, ct);
    /// <summary>Report the LLM tokens one model call used. The board prices it and counts it against your budget. Allowed when over budget.</summary>
    public Task<UsageReceipt> ReportUsageAsync(UsageReportInput usage, CancellationToken ct = default) => Call<UsageReceipt>(Tools.ReportUsage, usage, ct);
    /// <summary>Feedback people gave on your verdicts, findings and IOCs, and incidents resolved differently from your verdict (read only).</summary>
    public Task<AgentFeedbackResult> GetAgentFeedbackAsync(AgentFeedbackQuery? query = null, CancellationToken ct = default) =>
        Call<AgentFeedbackResult>(Tools.GetAgentFeedback, query ?? new AgentFeedbackQuery(), ct);

    public ValueTask DisposeAsync() => _transport.DisposeAsync();

    private sealed class BearerHandler(BoardOptions o) : DelegatingHandler
    {
        private readonly TokenCredential? _cred = o.DevPrincipal is null ? o.Credential ?? new DefaultAzureCredential() : null;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var token = o.DevPrincipal is { } dev
                ? $"dev:{dev}"
                : (await _cred!.GetTokenAsync(new TokenRequestContext([$"{o.Audience}/.default"]), ct)).Token;
            request.Headers.Authorization = new("Bearer", token);
            return await base.SendAsync(request, ct);
        }
    }
}

/// <summary>Where tool calls go. The MCP transport in production; an in-memory fake in tests.</summary>
public interface IBoardTransport : IAsyncDisposable
{
    Task<string> CallAsync(string tool, IReadOnlyDictionary<string, object?> args, CancellationToken ct);
}

internal sealed class McpTransport(McpClient client) : IBoardTransport
{
    public McpClient Client => client;

    public async Task<string> CallAsync(string tool, IReadOnlyDictionary<string, object?> args, CancellationToken ct)
    {
        var result = await client.CallToolAsync(tool, args, cancellationToken: ct);
        var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(c => c.Text));
        return result.IsError == true && !text.StartsWith("error:", StringComparison.Ordinal) ? $"error: {text}" : text;
    }

    public ValueTask DisposeAsync() => client.DisposeAsync();
}
