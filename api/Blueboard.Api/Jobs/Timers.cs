using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Webhooks;
using Blueboard.Api.Ops;
using Blueboard.Api.Intel;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Blueboard.Api.Jobs;

/// <summary>
/// Background work. Timer triggers run on one instance at a time (singleton lock in host storage);
/// a Postgres advisory lock makes that hold even across deployment slots.
/// </summary>
public sealed class Timers(Db db, Ingest ingest, Broker broker, WebhookService hooks, Notifier notifier, AuditExporter auditExport, PlaybookRunner playbooks, IntelService intel, Retention retention, Participants participants, Settings settings, ILogger<Timers> log,
    Agents.AgentBudgets? budgets = null, Agents.AgentRisk? risk = null, Agents.AgentTrace? trace = null, Agents.ObservabilitySettingsStore? observability = null)
{
    private const long LockKey = 7_340_001;
    /// <summary>The webhook loop has its own lock so a slow ingest never delays an agent's wake-up.</summary>
    private const long WebhookLockKey = 7_340_004;
    private const long NotifyLockKey = 7_340_005;
    private const long AuditLockKey = 7_340_006;
    /// <summary>Threat intel runs take their own lock, so a slow feed never holds up incident ingest.</summary>
    private const long IntelLockKey = 7_340_010;
    private const long RetentionLockKey = 7_340_011;
    /// <summary>Agent observability (budgets sweep, risk scores, trace retention): its own lock.</summary>
    private const long AgentObservabilityLockKey = 7_340_017;

    [Function("ingest-incidents")]
    public async Task IngestIncidents([TimerTrigger("0 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!settings.IngestEnabled) return;
        await WithLock(LockKey, async () =>
        {
            var kv = new KvState(db);
            try
            {
                var r = await ingest.RunOnceAsync(ct);
                await kv.SetAsync(KvState.IngestLastSuccess, new Setup.IngestRun(DateTimeOffset.UtcNow, r.Fetched), ct);
                log.LogInformation("ingest {@Result}", r);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // The setup page shows this; the message is Graph's error text, never a token.
                var msg = ex is BoardException ? ex.Message : ex.GetType().Name;
                await kv.SetAsync(KvState.IngestLastError, new Setup.IngestRun(DateTimeOffset.UtcNow, 0, msg.Length > 300 ? msg[..300] : msg), CancellationToken.None);
                throw;
            }
        }, ct);
    }

    [Function("recover-actions")]
    public async Task RecoverActions([TimerTrigger("30 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        await WithLock(LockKey, async () =>
        {
            var (resumed, interrupted) = await broker.RecoverAsync(ct);
            if (resumed + interrupted > 0) log.LogWarning("action recovery: resumed {Resumed}, interrupted {Interrupted}", resumed, interrupted);
            var expired = await broker.ExpireDueAsync(ct);
            if (expired > 0) log.LogInformation("expired {Expired} actions that were not decided in time", expired);
        }, ct);
    }

    /// <summary>
    /// Scheduled follow-ups and webhook delivery, every 2 seconds so a mention reaches a subscribed agent within 5.
    /// An idle tick is one indexed query; on Flex Consumption that is billed per execution, a few cents a day.
    /// </summary>
    [Function("agent-wakeups")]
    public async Task AgentWakeups([TimerTrigger("*/2 * * * * *")] TimerInfo timer, CancellationToken ct)
    {
        await WithLock(WebhookLockKey, async () =>
        {
            var r = await hooks.RunOnceAsync(ct);
            log.LogDebug("agent wake-ups {@Result}", r);
        }, ct);
    }

    /// <summary>Notifications (approvals and board messages): every 15 seconds, so a new request or question is announced within 30. The function name is kept for existing alerts.</summary>
    [Function("notify-approvers")]
    public async Task NotifyApprovers([TimerTrigger("*/15 * * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (notifier.Sinks().Count == 0) return;
        await WithLock(NotifyLockKey, async () =>
        {
            var sent = await notifier.RunOnceAsync(ct);
            if (sent > 0) log.LogInformation("sent {Count} notification(s)", sent);
        }, ct);
    }

    /// <summary>Audit log to Sentinel (production profile): every minute, so rows land within about five.</summary>
    [Function("export-audit")]
    public async Task ExportAudit([TimerTrigger("45 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!auditExport.Enabled) return;
        await WithLock(AuditLockKey, async () =>
        {
            var n = await auditExport.RunOnceAsync(ct);
            if (n > 0) log.LogInformation("exported {Count} audit row(s)", n);
        }, ct);
    }

    /// <summary>Backstop for playbook steps whose prerequisites were completed outside the API (e.g. a lease edge case).</summary>
    [Function("unlock-playbook-steps")]
    public async Task UnlockPlaybookSteps([TimerTrigger("15 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        await WithLock(LockKey, async () =>
        {
            var posted = await playbooks.UnlockPendingAsync(ct);
            if (posted > 0) log.LogInformation("posted {Count} unlocked playbook steps", posted);
        }, ct);
    }


    /// <summary>Daily lifecycle, outside Australian business hours: inactive principals (INACTIVE_DISABLE_DAYS), then data retention (RETENTION_DAYS).</summary>
    [Function("retention")]
    public async Task RetentionSweep([TimerTrigger("0 0 16 * * *")] TimerInfo timer, CancellationToken ct) // 02:00 or 03:00 in Sydney
    {
        if (settings.InactiveDisableDays > 0)
            await WithLock(RetentionLockKey, async () =>
            {
                var off = await participants.DisableInactiveAsync(settings.InactiveDisableDays, ct);
                if (off.Count > 0) log.LogWarning("disabled {Count} inactive principal(s): {Handles}", off.Count, string.Join(", ", off));
            }, ct);
        if (!retention.Enabled) return;
        await WithLock(RetentionLockKey, async () =>
        {
            var kv = new KvState(db);
            try
            {
                var r = await retention.RunAsync(dryRun: false, ct: ct);
                await kv.SetAsync(Retention.LastRunKey, r, ct);
                log.LogInformation("retention {@Result}", r);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                var msg = ex is BoardException ? ex.Message : ex.GetType().Name;
                await kv.SetAsync(Retention.LastRunKey, new RetentionResult(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, settings.RetentionDays, false, 0, 0, 0, 0, msg), CancellationToken.None);
                throw;
            }
        }, ct);
    }

    [Function("ti-feeds")]
    public async Task IntelFeeds([TimerTrigger("0 */15 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!settings.Ti.PwnWatch && !settings.Ti.Kev) return;
        await WithLock(IntelLockKey, async () => log.LogInformation("threat intel feeds {@Result}", await intel.RunFeedsAsync(ct)), ct);
    }

    [Function("ti-sentinel-auto")]
    public async Task IntelSentinelAuto([TimerTrigger("15 */2 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!settings.Ti.Sentinel) return;
        await WithLock(IntelLockKey, async () =>
        {
            try
            {
                var n = await intel.AutoEnrichSentinelAsync(ct);
                if (n > 0) log.LogInformation("Sentinel TI auto-enrich posted {Count} finding(s)", n);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.LogWarning(ex, "Sentinel TI auto-enrich failed");
            }
        }, ct);
    }

    [Function("ti-daily")]
    public async Task IntelDaily([TimerTrigger("0 30 17 * * *")] TimerInfo timer, CancellationToken ct) // 03:30 or 04:30 in Sydney
    {
        if (!settings.Ti.Epss && !settings.Ti.Exposure) return;
        await WithLock(IntelLockKey, async () => log.LogInformation("threat intel daily {@Result}", await intel.RunDailyAsync(ct)), ct);
    }

    [Function("ti-cvewatch-recheck")]
    public async Task CveWatchRecheck([TimerTrigger("0 0 18 1 * *")] TimerInfo timer, CancellationToken ct) =>
        await WithLock(IntelLockKey, async () => log.LogInformation("cve.watch re-check: {Status}", await intel.RecheckCveWatchAsync(ct)), ct);

    /// <summary>
    /// Agent observability, every 10 minutes: re-check budgets (a new UTC day or month lifts a block, an expired top-up
    /// can impose one), recompute agent risk scores (alert / quarantine per the admin thresholds) and, once an hour,
    /// delete tool-call traces older than the retention setting (default 30 days).
    /// </summary>
    [Function("agent-observability")]
    public async Task AgentObservability([TimerTrigger("0 */10 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (budgets is null || risk is null || trace is null || observability is null) return;
        await WithLock(AgentObservabilityLockKey, async () =>
        {
            var blocked = await budgets.SweepAsync(ct);
            var scored = await risk.RecomputeAllAsync(ct);
            log.LogInformation("agent observability: {Blocked} agent(s) over budget, {Scored} risk score(s) recomputed", blocked, scored);
            if (DateTimeOffset.UtcNow.Minute < 10)
            {
                var days = (await observability.GetAsync(ct)).TraceRetentionDays;
                var purged = await trace.PurgeAsync(days, ct);
                if (purged > 0) log.LogInformation("deleted {Count} agent trace row(s) older than {Days} days", purged, days);
            }
        }, ct);
    }

    private async Task WithLock(long key, Func<Task> work, CancellationToken ct)
    {
        await using var conn = await db.OpenAsync(ct);
        await using (var c = new NpgsqlCommand("select pg_try_advisory_lock(@k)", conn))
        {
            c.Parameters.AddWithValue("k", key);
            if (await c.ExecuteScalarAsync(ct) is not true) return;
        }
        try { await work(); }
        finally
        {
            await using var u = new NpgsqlCommand("select pg_advisory_unlock(@k)", conn);
            u.Parameters.AddWithValue("k", key);
            await u.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }
}
