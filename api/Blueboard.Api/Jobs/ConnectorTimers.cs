using Blueboard.Api.Connectors;
using Blueboard.Api.Data;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Blueboard.Api.Jobs;

/// <summary>
/// Connector sync every minute (docs/INTEGRATIONS.md): open tickets for incidents that meet the criteria, write board
/// events to linked tickets, resolve tickets, enrich new incidents' users from Okta, purge old inbound nonces. Its own
/// advisory lock, so a slow ticketing system never holds up ingest or webhooks. Nothing runs when no connector is set.
/// </summary>
public sealed class ConnectorTimers(Db db, ConnectorHub hub, ILogger<ConnectorTimers> log)
{
    private const long ConnectorLockKey = 7_340_019;

    [Function("connector-sync")]
    public async Task Sync([TimerTrigger("20 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        if (!hub.AnyEnabled) return;
        await using var conn = await db.OpenAsync(ct);
        await using (var c = new NpgsqlCommand("select pg_try_advisory_lock(@k)", conn))
        {
            c.Parameters.AddWithValue("k", ConnectorLockKey);
            if (await c.ExecuteScalarAsync(ct) is not true) return;
        }
        try
        {
            log.LogInformation("connector sync {@Result}", await hub.SyncOnceAsync(ct));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Each connector records its own error for the admin page; this keeps one failing system from failing the run.
            log.LogWarning(ex, "connector sync failed");
        }
        finally
        {
            await using var u = new NpgsqlCommand("select pg_advisory_unlock(@k)", conn);
            u.Parameters.AddWithValue("k", ConnectorLockKey);
            await u.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }
}
