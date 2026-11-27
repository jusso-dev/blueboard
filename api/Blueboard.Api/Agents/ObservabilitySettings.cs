using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Agents;

/// <summary>
/// Admin settings for agent observability (kv_state, Board.Admin people only, never MCP).
/// RiskAlertThreshold: a score at or above it posts one alert in #general and notifies approvers (on by default, 70).
/// RiskQuarantineThreshold: a score at or above it disables the agent through the normal disable path (releases its
/// claims, turns off its webhooks). Null (default) is off.
/// </summary>
public sealed record ObservabilitySettings(
    [property: Description("Days to keep MCP tool-call traces (1-365, default 30)")][Range(1, 365)] int TraceRetentionDays = 30,
    [property: Description("Post an alert when an agent's risk score reaches this (1-100); null turns alerts off")][Range(1, 100)] int? RiskAlertThreshold = 70,
    [property: Description("Disable (quarantine) an agent when its risk score reaches this (1-100); null is off (default)")][Range(1, 100)] int? RiskQuarantineThreshold = null);

/// <summary>A change to the settings, with the reason kept in the audit log.</summary>
public sealed record ObservabilitySettingsInput(
    [Description("Days to keep MCP tool-call traces (1-365)")][Range(1, 365)] int TraceRetentionDays,
    [Description("Alert threshold (1-100), or null for no alerts")][Range(1, 100)] int? RiskAlertThreshold,
    [Description("Auto-quarantine threshold (1-100), or null for off")][Range(1, 100)] int? RiskQuarantineThreshold,
    [Description("Why (5-500 characters)")][StringLength(500, MinimumLength = 5)] string Reason);

public sealed class ObservabilitySettingsStore(Db db, Audit audit)
{
    public const string Key = "agent_observability.settings";

    public async Task<ObservabilitySettings> GetAsync(CancellationToken ct = default) =>
        await new KvState(db).GetAsync<ObservabilitySettings>(Key, ct) ?? new ObservabilitySettings();

    public async Task<ObservabilitySettings> SetAsync(Principal me, ObservabilitySettingsInput input, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        if (!me.IsHuman) throw BoardException.Forbidden("only people can change agent observability settings");
        if (input.Reason.Trim() is not { Length: >= 5 and <= 500 } reason) throw new BoardException("reason must be 5–500 characters");
        if (input.RiskQuarantineThreshold is { } q && input.RiskAlertThreshold is { } a && q < a)
            throw new BoardException("the quarantine threshold must not be below the alert threshold");
        var before = await GetAsync(ct);
        var next = new ObservabilitySettings(input.TraceRetentionDays, input.RiskAlertThreshold, input.RiskQuarantineThreshold);
        await new KvState(db).SetAsync(Key, next, ct);
        await audit.WriteAsync(me.Id, "agent.settings_changed", Key, new { before, after = next, reason }, ct);
        return next;
    }
}
