using Azure.Core;
using Azure.Identity;
using Blueboard.Api.Core;
using Npgsql;

namespace Blueboard.Api.Data;

/// <summary>
/// Npgsql data source. In Azure the password is an Entra access token for the Function App's
/// managed identity (Azure Database for PostgreSQL, password auth disabled).
/// </summary>
public sealed class Db : IAsyncDisposable
{
    private const string PgScope = "https://ossrdbms-aad.database.windows.net/.default";
    private readonly NpgsqlDataSource _source;

    public Db(Settings settings, TokenCredential? credential = null)
    {
        var csb = settings.DatabaseUrl is { } url
            ? FromUrl(url)
            : new NpgsqlConnectionStringBuilder
            {
                Host = settings.PgHost ?? throw new InvalidOperationException("set DATABASE_URL or PGHOST"),
                Username = settings.PgUser,
                Database = settings.PgDatabase,
                SslMode = SslMode.Require,
            };
        csb.MaxPoolSize = 20;
        var builder = new NpgsqlDataSourceBuilder(csb.ConnectionString);
        if (settings.PgEntraAuth)
        {
            var cred = credential ?? new DefaultAzureCredential();
            builder.UsePeriodicPasswordProvider(
                async (_, ct) => (await cred.GetTokenAsync(new TokenRequestContext([PgScope]), ct)).Token,
                TimeSpan.FromMinutes(50),
                TimeSpan.FromSeconds(10));
        }
        _source = builder.Build();
    }

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
