using Blueboard.Api.Core;
using Npgsql;

namespace Blueboard.Api.Data;

/// <summary>
/// Applies db/migrations/*.sql in order, once each, under an advisory lock. With a separate migration role
/// (PG_MIGRATE_USER or DATABASE_MIGRATE_URL) the migrations run as that role, and the board's runtime role is then
/// created if needed (Entra: pgaadauth) and made a member of blueboard_app (db/migrations/009).
/// </summary>
public sealed class Migrator(Db db, Settings? settings = null)
{
    public async Task<IReadOnlyList<string>> RunAsync(string dir, CancellationToken ct = default)
    {
        if (settings is null || !Db.SeparateMigrationRole(settings)) return await ApplyAsync(db, dir, null, ct);
        await using var owner = Db.ForMigrations(settings);
        // Under the same advisory lock, so two instances starting together don't race the role grant.
        return await ApplyAsync(owner, dir, conn => EnsureRuntimeRoleAsync(conn, settings, ct), ct);
    }

    private static async Task<IReadOnlyList<string>> ApplyAsync(Db db, string dir, Func<NpgsqlConnection, Task>? after, CancellationToken ct)
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
            if (after is not null) await after(conn);
            return done;
        }
        finally
        {
            await using var unlock = new NpgsqlCommand("select pg_advisory_unlock(7340002)", conn);
            await unlock.ExecuteNonQueryAsync(ct);
        }
    }

    /// <summary>The role the board serves requests as: PGUSER, or the user in DATABASE_URL.</summary>
    public static string? RuntimeRole(Settings s) => s.DatabaseUrl is { } url ? Db.FromUrl(url).Username : s.PgUser;

    private static async Task EnsureRuntimeRoleAsync(NpgsqlConnection conn, Settings s, CancellationToken ct)
    {
        var role = RuntimeRole(s);
        if (string.IsNullOrEmpty(role)) return;
        if (await ScalarAsync(conn, "select current_user::text", ct) == role) return; // one role for both: nothing to separate
        if (!await ExistsAsync(conn, "select 1 from pg_roles where rolname = 'blueboard_app'", null, ct))
            throw new InvalidOperationException(
                "a separate migration role is configured but blueboard_app doesn't exist: the migration role needs CREATEROLE (db/migrations/009)");

        if (!await ExistsAsync(conn, "select 1 from pg_roles where rolname = @r", role, ct))
        {
            if (!s.PgEntraAuth || s.PgRuntimePrincipalId is null)
                throw new InvalidOperationException($"database role {role} does not exist: create it (LOGIN), or set PG_RUNTIME_PRINCIPAL_ID");
            // Azure Database for PostgreSQL: the Entra admin creates Entra roles from the postgres database.
            await using var admin = Db.ForMigrations(s, database: "postgres");
            await using var a = await admin.OpenAsync(ct);
            await using var create = new NpgsqlCommand("select * from pg_catalog.pgaadauth_create_principal_with_oid(@r, @oid, 'service', false, false)", a);
            create.Parameters.AddWithValue("r", role);
            create.Parameters.AddWithValue("oid", s.PgRuntimePrincipalId);
            await create.ExecuteNonQueryAsync(ct);
        }
        const string member = """
            select 1 from pg_auth_members m join pg_roles r on r.oid = m.member join pg_roles g on g.oid = m.roleid
            where r.rolname = @r and g.rolname = 'blueboard_app'
            """;
        if (await ExistsAsync(conn, member, role, ct)) return;
        await using var grant = new NpgsqlCommand($"grant blueboard_app to {QuoteIdent(role)}", conn);
        await grant.ExecuteNonQueryAsync(ct);
    }

    private static async Task<bool> ExistsAsync(NpgsqlConnection conn, string sql, string? role, CancellationToken ct)
    {
        await using var c = new NpgsqlCommand(sql, conn);
        if (role is not null) c.Parameters.AddWithValue("r", role);
        return await c.ExecuteScalarAsync(ct) is not null;
    }

    private static async Task<string?> ScalarAsync(NpgsqlConnection conn, string sql, CancellationToken ct)
    {
        await using var c = new NpgsqlCommand(sql, conn);
        return (string?)await c.ExecuteScalarAsync(ct);
    }

    internal static string QuoteIdent(string name) => "\"" + name.Replace("\"", "\"\"") + "\"";
}
