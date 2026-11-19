using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api.Data;

/// <summary>
/// Applies pending db/migrations when a worker starts. Migrations only add (tables, columns, indexes), take
/// a Postgres advisory lock, and skip anything already applied, so concurrent instances are safe.
/// </summary>
public sealed class MigrateOnStart(Migrator migrator, ILogger<MigrateOnStart> log) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        try
        {
            var applied = await migrator.RunAsync(Path.Combine(AppContext.BaseDirectory, "migrations"), ct);
            if (applied.Count > 0) log.LogWarning("applied migrations {Migrations}", string.Join(", ", applied));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Don't crash the worker: /api/healthz reports the database state.
            log.LogError(ex, "database migration failed");
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
