using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Intel;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Blueboard.Api.Jobs;

/// <summary>
/// Background work. Timer triggers run on one instance at a time (singleton lock in host storage);
/// a Postgres advisory lock makes that hold even across deployment slots.
/// </summary>
public sealed class Timers(Db db, Ingest ingest, Broker broker, IntelService intel, Settings settings, ILogger<Timers> log)
{
    private const long LockKey = 7_340_001;
    /// <summary>Threat intel runs take their own lock, so a slow feed never holds up incident ingest.</summary>
    private const long IntelLockKey = 7_340_010;

    [Function("ingest-incidents")]
    public async Task IngestIncidents([TimerTrigger("0 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!settings.IngestEnabled) return;
        await WithLock(async () =>
        {
            var r = await ingest.RunOnceAsync(ct);
            log.LogInformation("ingest {@Result}", r);
        }, ct);
    }

    [Function("recover-actions")]
    public async Task RecoverActions([TimerTrigger("30 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        await WithLock(async () =>
        {
            var (resumed, interrupted) = await broker.RecoverAsync(ct);
            if (resumed + interrupted > 0) log.LogWarning("action recovery: resumed {Resumed}, interrupted {Interrupted}", resumed, interrupted);
        }, ct);
    }

    [Function("ti-feeds")]
    public async Task IntelFeeds([TimerTrigger("0 */15 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!settings.Ti.PwnWatch && !settings.Ti.Kev) return;
        await WithLock(async () => log.LogInformation("threat intel feeds {@Result}", await intel.RunFeedsAsync(ct)), ct, IntelLockKey);
    }

    [Function("ti-sentinel-auto")]
    public async Task IntelSentinelAuto([TimerTrigger("15 */2 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!settings.Ti.Sentinel) return;
        await WithLock(async () =>
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
        }, ct, IntelLockKey);
    }

    [Function("ti-daily")]
    public async Task IntelDaily([TimerTrigger("0 30 17 * * *")] TimerInfo timer, CancellationToken ct) // 03:30 or 04:30 in Sydney
    {
        if (!settings.Ti.Epss && !settings.Ti.Exposure) return;
        await WithLock(async () => log.LogInformation("threat intel daily {@Result}", await intel.RunDailyAsync(ct)), ct, IntelLockKey);
    }

    [Function("ti-cvewatch-recheck")]
    public async Task CveWatchRecheck([TimerTrigger("0 0 18 1 * *")] TimerInfo timer, CancellationToken ct) =>
        await WithLock(async () => log.LogInformation("cve.watch re-check: {Status}", await intel.RecheckCveWatchAsync(ct)), ct, IntelLockKey);

    private async Task WithLock(Func<Task> work, CancellationToken ct, long key = LockKey)
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
