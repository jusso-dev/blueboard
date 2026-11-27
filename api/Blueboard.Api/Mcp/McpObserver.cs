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
    public Task BeforeAsync(Principal me, string tool, JsonElement args, CancellationToken ct = default)
    {
        var outcome = tool == Tools.CompleteClaim && args.ValueKind == JsonValueKind.Object && args.TryGetProperty("outcome", out var o) && o.ValueKind == JsonValueKind.String
            ? o.GetString() : null;
        return budgets.EnforceAsync(me, tool, outcome, ct);
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
            _log.LogWarning(ex, "metering for {Tool} failed", e.Tool);
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
