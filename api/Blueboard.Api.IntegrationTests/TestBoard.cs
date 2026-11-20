using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Npgsql;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>
/// A real board on a throwaway PostgreSQL database: migrations applied, dev principals seeded, a sample incident
/// ingested. Services are wired the way Program.cs wires them, with the broker in dry-run mode.
/// </summary>
public sealed class TestBoard : IAsyncLifetime
{
    public static string? ServerUrl => Environment.GetEnvironmentVariable("BLUEBOARD_TEST_DATABASE_URL");
    public const string SkipReason = "set BLUEBOARD_TEST_DATABASE_URL to run integration tests";

    private readonly string _dbName = $"bbtest_{Guid.NewGuid():N}"[..20];
    public Settings Settings { get; private set; } = null!;
    public Db Db { get; private set; } = null!;
    public Audit Audit { get; private set; } = null!;
    public BoardService Board { get; private set; } = null!;
    public SystemPrincipal System { get; private set; } = null!;
    public MsClient Ms { get; private set; } = null!;
    public Policy Policy { get; set; } = new();
    public Broker Broker => new(Db, Audit, Board, Ms, Settings, Policy, System);
    public Search Search => new(Db, Board);
    public Reporting Reporting => new(Db);
    public PlaybookSet Playbooks { get; } = global::Blueboard.Api.Board.Playbooks.Load(Path.Combine(AppContext.BaseDirectory, "playbooks"));
    public PlaybookRunner Runner => new(Db, Board, System, Playbooks);
    public IncidentQueries Incidents => new(Db, Board, Playbooks);
    public Ingest Ingest => new(Db, Board, Ms, System, Settings, Runner);
    public Guid IncidentId { get; private set; }
    public const string IncidentGraphId = "90210";
    public const string Device = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";

    public async ValueTask InitializeAsync()
    {
        if (ServerUrl is null) return;
        var server = Db.FromUrl(ServerUrl);
        await using (var admin = new NpgsqlConnection(server.ConnectionString))
        {
            await admin.OpenAsync();
            await using var c = new NpgsqlCommand($"create database {_dbName}", admin);
            await c.ExecuteNonQueryAsync();
        }
        var url = new UriBuilder(ServerUrl) { Path = "/" + _dbName }.Uri.ToString();
        Settings = new Settings { DatabaseUrl = url, DevAuth = true, ClaimLeaseSeconds = 600 };
        Db = new Db(Settings);
        await new Migrator(Db).RunAsync(Path.Combine(AppContext.BaseDirectory, "migrations"));
        Audit = new Audit(Db);
        Board = new BoardService(Db, Audit, Settings);
        System = new SystemPrincipal(Db);
        Ms = new MsClient(new HttpClient());
        foreach (var (h, n, k, roles) in Principals)
        {
            await using var cmd = Db.Command("insert into principals (handle, display_name, kind, roles) values (@h, @n, @k, @r)")
                .With("h", h).With("n", n).With("k", k).With("r", roles);
            await cmd.ExecuteNonQueryAsync();
        }
        await Ingest.UpsertAsync(SampleIncident());
        IncidentId = (await Board.ResolveIncidentAsync(IncidentGraphId))!.Value;
    }

    public async ValueTask DisposeAsync()
    {
        if (ServerUrl is null) return;
        await Db.DisposeAsync();
        NpgsqlConnection.ClearAllPools();
        await using var admin = new NpgsqlConnection(Db.FromUrl(ServerUrl).ConnectionString);
        await admin.OpenAsync();
        await using var c = new NpgsqlCommand($"drop database if exists {_dbName} with (force)", admin);
        await c.ExecuteNonQueryAsync();
    }

    public static readonly (string Handle, string Name, string Kind, string[] Roles)[] Principals =
    [
        ("analyst", "Analyst", "human", ["poster", "hunter", "requester", "approver", "admin"]),
        ("analyst2", "Second Analyst", "human", ["poster", "hunter", "requester", "approver"]),
        ("agent", "Agent", "agent", ["poster", "hunter", "requester"]),
        ("agent2", "Agent Two", "agent", ["poster", "hunter", "requester"]),
        ("reader", "Reader", "human", ["poster"]),
    ];

    public async Task<Principal> As(string handle)
    {
        await using var cmd = Db.Command("select id, handle, display_name, kind, roles from principals where handle = @h").With("h", handle);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) throw new InvalidOperationException($"no principal {handle}");
        return new Principal(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<string[]>(4));
    }

    public async Task<long> ScalarAsync(string sql, params (string, object?)[] args)
    {
        await using var cmd = Db.Command(sql);
        foreach (var (k, v) in args) cmd.With(k, v);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    public static JsonElement SampleIncident(string id = IncidentGraphId) => JsonSerializer.SerializeToElement(new Dictionary<string, object>
    {
        ["id"] = id,
        ["displayName"] = "Suspicious PowerShell download on WS-042",
        ["severity"] = "high",
        ["status"] = "active",
        ["createdDateTime"] = DateTimeOffset.UtcNow.AddMinutes(-30),
        ["lastUpdateDateTime"] = DateTimeOffset.UtcNow,
        ["incidentWebUrl"] = $"https://security.microsoft.com/incidents/{id}",
        ["alerts"] = new object[]
        {
            new Dictionary<string, object>
            {
                ["id"] = $"da{id}", ["title"] = "Suspicious PowerShell command line", ["severity"] = "high", ["category"] = "Execution",
                ["evidence"] = new object[]
                {
                    new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.deviceEvidence", ["mdeDeviceId"] = Device, ["deviceDnsName"] = "ws-042.contoso.com", ["hostName"] = "ws-042" },
                    new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.userEvidence", ["userAccount"] = new Dictionary<string, object> { ["userPrincipalName"] = "ana@contoso.com", ["azureAdUserId"] = "11111111-1111-1111-1111-111111111111", ["accountName"] = "ana" } },
                    new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.ipEvidence", ["ipAddress"] = "203.0.113.50" },
                    new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.urlEvidence", ["url"] = "https://bad.example/payload.ps1" },
                },
            },
        },
    });
}

/// <summary>Skips when no test database is configured.</summary>
public sealed class DbFactAttribute : FactAttribute
{
    public DbFactAttribute(
        [System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (TestBoard.ServerUrl is null) Skip = TestBoard.SkipReason;
    }
}
