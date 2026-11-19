namespace Blueboard.Api.Core;

/// <summary>App settings (environment variables). Read once at startup.</summary>
public sealed record Settings
{
    public string? DatabaseUrl { get; init; }
    public string? PgHost { get; init; }
    public string? PgUser { get; init; }
    public string PgDatabase { get; init; } = "blueboard";
    public bool PgEntraAuth { get; init; }

    public string? TenantId { get; init; }
    /// <summary>App ID URI of the board API, e.g. api://blueboard-prod. Agent tokens must carry this audience.</summary>
    public string? ApiAudience { get; init; }
    /// <summary>Client id of the board API app registration (also accepted as an audience).</summary>
    public string? ApiClientId { get; init; }

    /// <summary>Local only: accept "Bearer dev:&lt;handle&gt;" and the x-dev-principal header. Refused in Azure.</summary>
    public bool DevAuth { get; init; }
    /// <summary>Trust the x-ms-client-principal header. Only true when the Function App is reachable solely from its linked Static Web App.</summary>
    public bool TrustSwaPrincipal { get; init; }

    public bool IngestEnabled { get; init; }
    public int IngestLookbackHours { get; init; } = 24;
    public bool BrokerExecute { get; init; }
    public string? PolicyFile { get; init; }
    public int ClaimLeaseSeconds { get; init; } = 600;

    public static Settings FromEnvironment()
    {
        static string? Env(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : null;
        static bool Flag(string k) => Env(k) is "true" or "1" or "True";
        static int Int(string k, int d) => int.TryParse(Env(k), out var v) ? v : d;

        var s = new Settings
        {
            DatabaseUrl = Env("DATABASE_URL"),
            PgHost = Env("PGHOST"),
            PgUser = Env("PGUSER"),
            PgDatabase = Env("PGDATABASE") ?? "blueboard",
            PgEntraAuth = Flag("PG_ENTRA_AUTH"),
            TenantId = Env("AZURE_TENANT_ID"),
            ApiAudience = Env("BOARD_API_AUDIENCE"),
            ApiClientId = Env("BOARD_API_CLIENT_ID"),
            DevAuth = Flag("DEV_AUTH"),
            TrustSwaPrincipal = Flag("TRUST_SWA_PRINCIPAL"),
            IngestEnabled = Flag("INGEST_ENABLED"),
            IngestLookbackHours = Int("INGEST_LOOKBACK_HOURS", 24),
            BrokerExecute = Flag("BROKER_EXECUTE"),
            PolicyFile = Env("BLUEBOARD_POLICY_FILE") ?? WritePolicyFromSetting(Env("BLUEBOARD_POLICY_JSON")),
            ClaimLeaseSeconds = Int("CLAIM_LEASE_SECONDS", 600),
        };
        // WEBSITE_INSTANCE_ID is set on every Azure Functions host: never allow dev auth there.
        if (s.DevAuth && Env("WEBSITE_INSTANCE_ID") is not null)
            throw new InvalidOperationException("DEV_AUTH must not be enabled in Azure");
        return s;
    }

    /// <summary>In Azure the policy arrives as a (secret) app setting; write it to a private temp file once.</summary>
    private static string? WritePolicyFromSetting(string? json)
    {
        if (json is null) return null;
        var path = Path.Combine(Path.GetTempPath(), "blueboard-policy.json");
        File.WriteAllText(path, json);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }
}
