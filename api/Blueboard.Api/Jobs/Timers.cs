using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Webhooks;
using Blueboard.Api.Ops;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Blueboard.Api.Jobs;

/// <summary>
/// Background work. Timer triggers run on one instance at a time (singleton lock in host storage);
/// a Postgres advisory lock makes that hold even across deployment slots.
/// </summary>
public sealed class Timers(Db db, Ingest ingest, Broker broker, WebhookService hooks, Notifier notifier, AuditExporter auditExport, Settings settings, ILogger<Timers> log)
{
    private const long LockKey = 7_340_001;
    /// <summary>The webhook loop has its own lock so a slow ingest never delays an agent's wake-up.</summary>
    private const long WebhookLockKey = 7_340_004;
    private const long NotifyLockKey = 7_340_005;
    private const long AuditLockKey = 7_340_006;

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

    /// <summary>Approver notifications: every 15 seconds, so a new request is announced within 30.</summary>
    [Function("notify-approvers")]
    public async Task NotifyApprovers([TimerTrigger("*/15 * * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (notifier.Sinks().Count == 0) return;
        await WithLock(NotifyLockKey, async () =>
        {
            var sent = await notifier.RunOnceAsync(ct);
            if (sent > 0) log.LogInformation("sent {Count} approver notification(s)", sent);
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
