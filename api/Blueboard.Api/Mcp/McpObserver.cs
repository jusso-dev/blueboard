using System.Text.Json;
using Blueboard.Api.Agents;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blueboard.Api.Mcp;

/// <summary>
/// The single hook every MCP tool call passes through (BoardTools.Call), so tools added later are covered with no
/// per-tool code. Before the tool runs: the hard budget cap (<see cref="AgentBudgets.EnforceAsync"/>). After it runs,
/// success or failure: board-side metering, the tool-call trace and, for a post refused for carrying a secret, an
/// audit row the risk score counts. The after-hook never throws: observability must not fail an agent's call.
/// </summary>
public sealed class McpObserver(AgentBudgets budgets, AgentTrace trace, Audit audit, ILogger<McpObserver>? log = null)
{
    private readonly ILogger _log = log ?? NullLogger<McpObserver>.Instance;

    /// <summary>Throws (status 402) when the caller is over budget and the tool isn't one it may still call.</summary>
    public Task BeforeAsync(Principal me, string tool, JsonElement args, CancellationToken ct = default) =>
        budgets.EnforceAsync(me, tool, tool == Tools.CompleteClaim ? ClaimOutcome(args) : null, ct);

    /// <summary>
    /// complete_claim's outcome exactly as the tool will read it (the same contract, so the same case-insensitive
    /// property match and last-wins duplicates), or null when the arguments wouldn't validate. Reading the raw JSON
    /// separately would let {"outcome":"release","OUTCOME":"done"} pass as a release and then run as done.
    /// </summary>
    internal static string? ClaimOutcome(JsonElement args)
    {
        try { return Contract.Read<CompleteClaimInput>(args).Outcome; }
        catch (ContractException) { return null; }
    }

    // ── REST calls by agents (Http/Endpoint.cs) ────────────────────────────────────────────────

    /// <summary>The REST equivalent of whoami: never budget-blocked or charged.</summary>
    public const string RestWhoAmI = "rest:GET /api/me";
    /// <summary>The REST claim route: exempt only for op=release, as complete_claim is.</summary>
    public const string RestClaim = "rest:POST /api/claims/{id}";

    /// <summary>
    /// The budget cap for an agent calling REST (<paramref name="label"/> is "rest:METHOD /api/route"). The same block
    /// as MCP; exempt: GET /api/me and releasing a claim (<paramref name="claimOp"/> as ClaimOp parses it).
    /// </summary>
    public Task BeforeRestAsync(Principal me, string label, string? claimOp, CancellationToken ct = default) =>
        label == RestWhoAmI || (label == RestClaim && claimOp == "release") ? Task.CompletedTask : budgets.EnforceAsync(me, label, null, ct);

    /// <summary>claims/{id}'s op exactly as the route reads it (ClaimOp), or null.</summary>
    internal static string? ClaimOp(JsonElement body)
    {
        try { return Contract.Read<ClaimOp>(body).Op; }
        catch (ContractException) { return null; }
    }

    public async Task AfterAsync(TraceEntry e, CancellationToken ct = default)
    {
        try
        {
            await budgets.MeterAsync(e.Principal.Id, e.Tool, e.Status != "ok", ct);
            if (e.Status == "secret_blocked" && e.Principal.Kind == "agent")
                await audit.WriteAsync(e.Principal.Id, "agent.secret_blocked", e.Tool, null, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "metering for {Tool} failed", Blueboard.Api.Ops.Notifier.OneLine(e.Tool, 120));
        }
        await trace.RecordAsync(e, ct);
    }

    /// <summary>Trace status for a BoardException the tool threw.</summary>
    public static string StatusOf(BoardException ex) => ex switch
    {
        { Bucket: "budget" } => "budget_blocked",
        { Bucket: SecretLeakBucket } => "secret_blocked",
        { Status: 429 } => "rate_limited",
        { Status: 401 or 403 } => "forbidden",
        _ => "error",
    };

    /// <summary>Marks a refusal for raw credentials (BoardService and MemoryService set it).</summary>
    public const string SecretLeakBucket = "secret_leak";

    /// <summary>The board message a tool result is about (a posted message, an action's request message), for trace links.</summary>
    public static Guid? MessageIdOf(object? result) => result switch
    {
        Message m => m.Id,
        ActionRow a => a.RequestMessageId,
        _ => null,
    };
}
