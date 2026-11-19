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

    public bool IngestEnabled { get; init; }
    public int IngestLookbackHours { get; init; } = 24;
    public bool BrokerExecute { get; init; }
    public string? PolicyFile { get; init; }
    public int ClaimLeaseSeconds { get; init; } = 600;

    /// <summary>
    /// Local demo only (docker-compose.demo.yml): Microsoft Graph and Defender calls go to a mock API. Needs DEV_AUTH
    /// as well, and is refused in Azure. The base URLs are only honoured when this is on.
    /// </summary>
    public bool DemoMode { get; init; }
    public string? GraphBaseUrl { get; init; }
    public string? DefenderBaseUrl { get; init; }

    /// <summary>Hosts agents may register webhook URLs on (exact match, https only). Empty: webhooks are off.</summary>
    public string[] WebhookAllowedHosts { get; init; } = [];
    /// <summary>Master key that per-subscription signing secrets are derived from (base64, 32+ bytes). Never logged.</summary>
    public string? WebhookSigningKey { get; init; }

    public static Settings FromEnvironment() => FromEnvironment(k => Environment.GetEnvironmentVariable(k));

    /// <summary>Reads settings from a variable source (tests pass a dictionary).</summary>
    public static Settings FromEnvironment(Func<string, string?> source)
    {
        string? Env(string k) => source(k) is { Length: > 0 } v ? v : null;
        bool Flag(string k) => Env(k) is "true" or "1" or "True";
        int Int(string k, int d) => int.TryParse(Env(k), out var v) ? v : d;

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
            IngestEnabled = Flag("INGEST_ENABLED"),
            IngestLookbackHours = Int("INGEST_LOOKBACK_HOURS", 24),
            BrokerExecute = Flag("BROKER_EXECUTE"),
            PolicyFile = Env("BLUEBOARD_POLICY_FILE") ?? WritePolicyFromSetting(Env("BLUEBOARD_POLICY_JSON")),
            ClaimLeaseSeconds = Int("CLAIM_LEASE_SECONDS", 600),
            DemoMode = Flag("DEMO_MODE"),
            GraphBaseUrl = Env("GRAPH_BASE_URL"),
            DefenderBaseUrl = Env("DEFENDER_BASE_URL"),
            WebhookAllowedHosts = (Env("WEBHOOK_ALLOWED_HOSTS") ?? "")
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(h => h.ToLowerInvariant()).ToArray(),
            WebhookSigningKey = Env("WEBHOOK_SIGNING_KEY"),
        };
        // WEBSITE_INSTANCE_ID is set on every Azure Functions host: never allow dev auth or the demo there.
        var inAzure = Env("WEBSITE_INSTANCE_ID") is not null;
        if (s.DevAuth && inAzure) throw new InvalidOperationException("DEV_AUTH must not be enabled in Azure");
        if (s.DemoMode && inAzure) throw new InvalidOperationException("DEMO_MODE must not be enabled in Azure");
        if (s.DemoMode && !s.DevAuth) throw new InvalidOperationException("DEMO_MODE needs DEV_AUTH=true (local demo only)");
        if ((s.GraphBaseUrl ?? s.DefenderBaseUrl) is not null && !s.DemoMode)
            throw new InvalidOperationException("GRAPH_BASE_URL / DEFENDER_BASE_URL are only allowed with DEMO_MODE=true and DEV_AUTH=true");
        if (s.WebhookSigningKey is { } key && (!IsBase64(key, out var bytes) || bytes < 32))
            throw new InvalidOperationException("WEBHOOK_SIGNING_KEY must be base64 of at least 32 random bytes");
        return s;
    }

    private static bool IsBase64(string s, out int bytes)
    {
        var buf = new byte[s.Length];
        var ok = Convert.TryFromBase64String(s, buf, out bytes);
        return ok;
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
