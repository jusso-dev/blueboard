using Npgsql;

namespace Blueboard.Api.Data;

/// <summary>Applies db/migrations/*.sql in order, once each, under an advisory lock.</summary>
public sealed class Migrator(Db db)
{
    public async Task<IReadOnlyList<string>> RunAsync(string dir, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await using (var lockCmd = new NpgsqlCommand("select pg_advisory_lock(7340002)", conn)) await lockCmd.ExecuteNonQueryAsync(ct);
        try
        {
            await using (var c = new NpgsqlCommand(
                "create table if not exists schema_migrations (name text primary key, applied_at timestamptz not null default now())", conn))
                await c.ExecuteNonQueryAsync(ct);

            var applied = new HashSet<string>();
            await using (var c = new NpgsqlCommand("select name from schema_migrations", conn))
            await using (var r = await c.ExecuteReaderAsync(ct))
                while (await r.ReadAsync(ct)) applied.Add(r.GetString(0));

            var done = new List<string>();
            foreach (var file in Directory.GetFiles(dir, "*.sql").Order(StringComparer.Ordinal))
            {
                var name = Path.GetFileName(file);
                if (applied.Contains(name)) continue;
                await using var tx = await conn.BeginTransactionAsync(ct);
                await using (var c = new NpgsqlCommand(await File.ReadAllTextAsync(file, ct), conn, tx)) await c.ExecuteNonQueryAsync(ct);
                await using (var c = new NpgsqlCommand("insert into schema_migrations (name) values (@n)", conn, tx))
                {
                    c.Parameters.AddWithValue("n", name);
                    await c.ExecuteNonQueryAsync(ct);
                }
                await tx.CommitAsync(ct);
                done.Add(name);
            }
            return done;
        }
        finally
        {
            await using var unlock = new NpgsqlCommand("select pg_advisory_unlock(7340002)", conn);
            await unlock.ExecuteNonQueryAsync(ct);
        }
    }
}
