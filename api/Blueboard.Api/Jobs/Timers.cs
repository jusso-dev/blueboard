using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Blueboard.Api.Jobs;

/// <summary>
/// Background work. Timer triggers run on one instance at a time (singleton lock in host storage);
/// a Postgres advisory lock makes that hold even across deployment slots.
/// </summary>
public sealed class Timers(Db db, Ingest ingest, Broker broker, PlaybookRunner playbooks, Settings settings, ILogger<Timers> log)
{
    private const long LockKey = 7_340_001;

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

    /// <summary>Backstop for playbook steps whose prerequisites were completed outside the API (e.g. a lease edge case).</summary>
    [Function("unlock-playbook-steps")]
    public async Task UnlockPlaybookSteps([TimerTrigger("45 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        await WithLock(async () =>
        {
            var posted = await playbooks.UnlockPendingAsync(ct);
            if (posted > 0) log.LogInformation("posted {Count} unlocked playbook steps", posted);
        }, ct);
    }

    private async Task WithLock(Func<Task> work, CancellationToken ct)
    {
        await using var conn = await db.OpenAsync(ct);
        await using (var c = new NpgsqlCommand("select pg_try_advisory_lock(@k)", conn))
        {
            c.Parameters.AddWithValue("k", LockKey);
            if (await c.ExecuteScalarAsync(ct) is not true) return;
        }
        try { await work(); }
        finally
        {
            await using var u = new NpgsqlCommand("select pg_advisory_unlock(@k)", conn);
            u.Parameters.AddWithValue("k", LockKey);
            await u.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }
}
