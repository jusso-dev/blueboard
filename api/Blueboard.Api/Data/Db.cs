using Azure.Core;
using Azure.Identity;
using Blueboard.Api.Core;
using Npgsql;

namespace Blueboard.Api.Data;

/// <summary>
/// Npgsql data source. In Azure the password is an Entra access token for a managed identity (Azure Database for
/// PostgreSQL, password auth disabled). The board serves requests as PGUSER (token for PG_CLIENT_ID); migrations run
/// as a different, schema-owning role when PG_MIGRATE_USER is set (<see cref="ForMigrations"/>), so the role that
/// serves requests can't alter tables or rewrite audit_log (db/migrations/009).
/// </summary>
public sealed class Db : IAsyncDisposable
{
    private const string PgScope = "https://ossrdbms-aad.database.windows.net/.default";
    private readonly NpgsqlDataSource _source;

    public Db(Settings settings, TokenCredential? credential = null)
        : this(Build(settings.DatabaseUrl, settings.PgHost, settings.PgUser, settings.PgDatabase), settings.PgEntraAuth,
            credential ?? (settings.PgEntraAuth ? Credential(settings.PgClientId) : null))
    {
    }

    private Db(NpgsqlConnectionStringBuilder csb, bool entra, TokenCredential? credential)
    {
        csb.MaxPoolSize = 20;
        var builder = new NpgsqlDataSourceBuilder(csb.ConnectionString);
        if (entra)
        {
            var cred = credential ?? new DefaultAzureCredential();
            builder.UsePeriodicPasswordProvider(
                async (_, ct) => (await cred.GetTokenAsync(new TokenRequestContext([PgScope]), ct)).Token,
                TimeSpan.FromMinutes(50),
                TimeSpan.FromSeconds(10));
        }
        _source = builder.Build();
    }

    /// <summary>True when migrations connect as a different role from the one that serves requests.</summary>
    public static bool SeparateMigrationRole(Settings s) => s.MigrateDatabaseUrl is not null || s.PgMigrateUser is not null;

    /// <summary>
    /// A data source for applying migrations: DATABASE_MIGRATE_URL (local, tests), or PG_MIGRATE_USER on PGHOST with
    /// the default identity's token (AZURE_CLIENT_ID, the PostgreSQL Entra admin). Without either, the runtime settings.
    /// </summary>
    public static Db ForMigrations(Settings s, TokenCredential? credential = null, string? database = null)
    {
        if (s.MigrateDatabaseUrl is { } url) return new Db(WithDatabase(FromUrl(url), database), false, null);
        if (s.PgMigrateUser is { } user)
            return new Db(WithDatabase(Build(null, s.PgHost, user, s.PgDatabase), database), s.PgEntraAuth,
                credential ?? (s.PgEntraAuth ? new DefaultAzureCredential() : null));
        return new Db(WithDatabase(Build(s.DatabaseUrl, s.PgHost, s.PgUser, s.PgDatabase), database), s.PgEntraAuth,
            credential ?? (s.PgEntraAuth ? Credential(s.PgClientId) : null));
    }

    private static NpgsqlConnectionStringBuilder WithDatabase(NpgsqlConnectionStringBuilder csb, string? database)
    {
        if (database is not null) csb.Database = database;
        return csb;
    }

    private static NpgsqlConnectionStringBuilder Build(string? url, string? host, string? user, string database) =>
        url is not null
            ? FromUrl(url)
            : new NpgsqlConnectionStringBuilder
            {
                Host = host ?? throw new InvalidOperationException("set DATABASE_URL or PGHOST"),
                Username = user,
                Database = database,
                SslMode = SslMode.Require,
            };

    /// <summary>The token source for a user-assigned identity by client id, or the default chain.</summary>
    private static TokenCredential Credential(string? clientId) => clientId is null
        ? new DefaultAzureCredential()
        : new DefaultAzureCredential(new DefaultAzureCredentialOptions { ManagedIdentityClientId = clientId });

    public NpgsqlDataSource Source => _source;

    public ValueTask<NpgsqlConnection> OpenAsync(CancellationToken ct = default) => _source.OpenConnectionAsync(ct);

    public NpgsqlCommand Command(string sql) => _source.CreateCommand(sql);

    public ValueTask DisposeAsync() => _source.DisposeAsync();

    /// <summary>postgres://user:pass@host:port/db → Npgsql connection string (local development).</summary>
    internal static NpgsqlConnectionStringBuilder FromUrl(string url)
    {
        var uri = new Uri(url);
        var userInfo = uri.UserInfo.Split(':', 2);
        return new NpgsqlConnectionStringBuilder
        {
            Host = uri.Host,
            Port = uri.Port > 0 ? uri.Port : 5432,
            Username = Uri.UnescapeDataString(userInfo[0]),
            Password = userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : null,
            Database = uri.AbsolutePath.TrimStart('/'),
            SslMode = SslMode.Prefer,
        };
    }
}

public static class DbExtensions
{
    public static NpgsqlCommand With(this NpgsqlCommand cmd, string name, object? value)
    {
        cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return cmd;
    }

    public static NpgsqlCommand WithJson(this NpgsqlCommand cmd, string name, object? value)
    {
        cmd.Parameters.Add(new NpgsqlParameter(name, NpgsqlTypes.NpgsqlDbType.Jsonb)
        {
            Value = value is null ? DBNull.Value : Json.Serialize(value),
        });
        return cmd;
    }

    public static T? Get<T>(this NpgsqlDataReader r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? default : r.GetFieldValue<T>(i);
    }
}
