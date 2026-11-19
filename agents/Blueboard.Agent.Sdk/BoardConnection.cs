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

    public static BoardOptions FromEnvironment(string? devPrincipalFallback = null)
    {
        static string? Env(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : null;
        return new BoardOptions
        {
            BoardUrl = new Uri(Env("BOARD_URL") ?? "http://localhost:7071"),
            Audience = Env("BOARD_API_AUDIENCE"),
            DevPrincipal = Env("BOARD_DEV_PRINCIPAL") ?? devPrincipalFallback,
        };
    }
}

/// <summary>A board tool failed (the board reports failures as "error: … (status N)" text). Status is the HTTP-style code.</summary>
public sealed class BoardToolException(string tool, string message, int status) : Exception($"{tool}: {message}")
{
    public string Tool { get; } = tool;
    public int Status { get; } = status;
    public bool IsConflict => Status == 409;
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
        return new BoardConnection(new McpTransport(await McpClient.CreateAsync(transport, cancellationToken: ct)));
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
    public Task<FeedResult> ReadFeedAsync(FeedQuery query, CancellationToken ct = default) => Call<FeedResult>(Tools.ReadFeed, query, ct);
    public Task<ThreadResult> GetThreadAsync(Guid messageId, CancellationToken ct = default) => Call<ThreadResult>(Tools.GetThread, new ThreadQuery(messageId), ct);
    public Task<Message> PostAsync(PostInput input, CancellationToken ct = default) => Call<Message>(Tools.PostMessage, input, ct);
    public Task<Message> ClaimAsync(Guid messageId, int? leaseSeconds = null, CancellationToken ct = default) => Call<Message>(Tools.ClaimMessage, new ClaimInput(messageId, leaseSeconds), ct);
    public Task<Message> RenewClaimAsync(Guid messageId, int? leaseSeconds = null, CancellationToken ct = default) => Call<Message>(Tools.RenewClaim, new ClaimInput(messageId, leaseSeconds), ct);
    public Task<Message> CompleteClaimAsync(Guid messageId, string outcome, CancellationToken ct = default) => Call<Message>(Tools.CompleteClaim, new CompleteClaimInput(messageId, outcome), ct);
    public Task<JsonElement> GetIncidentAsync(string incident, CancellationToken ct = default) => Call<JsonElement>(Tools.GetIncident, new IncidentQuery(incident), ct);
    public Task<JsonElement> RunHuntingQueryAsync(string query, string? timespan = null, CancellationToken ct = default) => Call<JsonElement>(Tools.RunHuntingQuery, new HuntInput(query, timespan), ct);
    public Task<JsonElement> LookupEntityAsync(string kind, string value, CancellationToken ct = default) => Call<JsonElement>(Tools.LookupEntity, new LookupInput(kind, value), ct);
    public Task<JsonElement> ListActionTypesAsync(CancellationToken ct = default) => Call<JsonElement>(Tools.ListActionTypes, null, ct);
    public Task<ActionRow> RequestActionAsync(ActionRequest request, CancellationToken ct = default) => Call<ActionRow>(Tools.RequestAction, request, ct);
    public Task<ActionRow> GetActionAsync(Guid actionId, CancellationToken ct = default) => Call<ActionRow>(Tools.GetAction, new ActionQuery(actionId), ct);
    public Task<Subscription> SubscribeAsync(SubscribeInput input, CancellationToken ct = default) => Call<Subscription>(Tools.Subscribe, input, ct);
    public Task<JsonElement> UnsubscribeAsync(Guid subscriptionId, CancellationToken ct = default) => Call<JsonElement>(Tools.Unsubscribe, new UnsubscribeInput(subscriptionId), ct);
    public Task<Followup> ScheduleFollowupAsync(Guid messageId, string note, int inMinutes, CancellationToken ct = default) => Call<Followup>(Tools.ScheduleFollowup, new FollowupInput(messageId, note, inMinutes), ct);

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
