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
    /// <summary>Where the policy came from, in words, for the setup page. Null when no policy is configured.</summary>
    public string? PolicySource { get; init; }

    /// <summary>Public base URL of the web app (deep links in notifications), e.g. https://blueboard-web-x.azurewebsites.net.</summary>
    public string? WebBaseUrl { get; init; }

    // Approver notifications (docs/OPERATIONS.md). URLs and the HMAC secret are app settings (Key Vault references
    // in the production profile) and are never logged or returned by the API.
    public string? NotifyTeamsWebhookUrl { get; init; }
    public string? NotifyWebhookUrl { get; init; }
    public string? NotifyWebhookSecret { get; init; }
    public string? NotifyMailFrom { get; init; }
    public string[] NotifyMailTo { get; init; } = [];
    /// <summary>Exact host names the Teams and webhook URLs may point at (https only).</summary>
    public string[] NotifyAllowedHosts { get; init; } = [];
    public int NotifyRemindMinutes { get; init; } = 15;

    // Audit export to Microsoft Sentinel through the Logs Ingestion API (production profile).
    public string? AuditDceEndpoint { get; init; }
    public string? AuditDcrId { get; init; }
    public string AuditStream { get; init; } = "Custom-BlueboardAudit_CL";

    public static Settings FromEnvironment()
    {
        static string? Env(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : null;
        static bool Flag(string k) => Env(k) is "true" or "1" or "True";
        static int Int(string k, int d) => int.TryParse(Env(k), out var v) ? v : d;
        static string[] List(string k) => (Env(k) ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

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
            PolicySource = Env("BLUEBOARD_POLICY_FILE") is { } f ? $"file {f}"
                : Env("BLUEBOARD_POLICY_JSON") is not null ? "app setting BLUEBOARD_POLICY_JSON" : null,
            WebBaseUrl = Env("BOARD_WEB_URL")?.TrimEnd('/'),
            NotifyTeamsWebhookUrl = Env("NOTIFY_TEAMS_WEBHOOK_URL"),
            NotifyWebhookUrl = Env("NOTIFY_WEBHOOK_URL"),
            NotifyWebhookSecret = Env("NOTIFY_WEBHOOK_SECRET"),
            NotifyMailFrom = Env("NOTIFY_MAIL_FROM"),
            NotifyMailTo = List("NOTIFY_MAIL_TO"),
            NotifyAllowedHosts = List("NOTIFY_ALLOWED_HOSTS"),
            NotifyRemindMinutes = Math.Max(1, Int("NOTIFY_REMIND_MINUTES", 15)),
            AuditDceEndpoint = Env("AUDIT_DCE_ENDPOINT"),
            AuditDcrId = Env("AUDIT_DCR_ID"),
            AuditStream = Env("AUDIT_STREAM") ?? "Custom-BlueboardAudit_CL",
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
