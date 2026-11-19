using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Webhooks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Blueboard.Api.Jobs;

/// <summary>
/// Background work. Timer triggers run on one instance at a time (singleton lock in host storage);
/// a Postgres advisory lock makes that hold even across deployment slots.
/// </summary>
public sealed class Timers(Db db, Ingest ingest, Broker broker, WebhookService hooks, Settings settings, ILogger<Timers> log)
{
    private const long LockKey = 7_340_001;
    /// <summary>The webhook loop has its own lock so a slow ingest never delays an agent's wake-up.</summary>
    private const long WebhookLockKey = 7_340_004;

    [Function("ingest-incidents")]
    public async Task IngestIncidents([TimerTrigger("0 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!settings.IngestEnabled) return;
        await WithLock(LockKey, async () =>
        {
            var r = await ingest.RunOnceAsync(ct);
            log.LogInformation("ingest {@Result}", r);
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
