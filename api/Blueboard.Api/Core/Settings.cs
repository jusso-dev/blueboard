namespace Blueboard.Api.Core;

/// <summary>App settings (environment variables). Read once at startup.</summary>
public sealed record Settings
{
    public string? DatabaseUrl { get; init; }
    public string? PgHost { get; init; }
    public string? PgUser { get; init; }
    public string PgDatabase { get; init; } = "blueboard";
    public bool PgEntraAuth { get; init; }
    /// <summary>
    /// Client id of the user-assigned identity the board queries PostgreSQL with (PGUSER, blueboard-id-db). Empty: the
    /// default identity (AZURE_CLIENT_ID).
    /// </summary>
    public string? PgClientId { get; init; }
    /// <summary>
    /// Database role that applies migrations and owns the tables: the PostgreSQL Entra admin (blueboard-id-api, token
    /// from the default identity). When set, PGUSER is a least-privilege member of blueboard_app (db/migrations/009).
    /// </summary>
    public string? PgMigrateUser { get; init; }
    /// <summary>Entra object id of the PGUSER identity, so migrations can create its database role if it's missing.</summary>
    public string? PgRuntimePrincipalId { get; init; }
    /// <summary>Local and tests: postgres:// URL migrations use instead of DATABASE_URL (a role that owns the schema).</summary>
    public string? MigrateDatabaseUrl { get; init; }

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
    /// <summary>Inline JSON policy passed via BLUEBOARD_POLICY_JSON (parsed in memory without temporary files).</summary>
    public string? PolicyJson { get; init; }
    /// <summary>Optional Microsoft Purview processContent data-security guard on non-system board posts: off | audit | block.</summary>
    public string PurviewGuardMode { get; init; } = "off";
    public int ClaimLeaseSeconds { get; init; } = 600;
    /// <summary>Where the policy came from, in words, for the setup page. Null when no policy is configured.</summary>
    public string? PolicySource { get; init; }
    /// <summary>Folder of playbook Markdown files. Defaults to the copy bundled with the Function App.</summary>
    public string PlaybooksDir { get; init; } = Path.Combine(AppContext.BaseDirectory, "playbooks");
    /// <summary>Threat intel and CVE sources (all off by default).</summary>
    public TiSettings Ti { get; init; } = new();

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
        string[] List(string k) => (Env(k) ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var s = new Settings
        {
            DatabaseUrl = Env("DATABASE_URL"),
            PgHost = Env("PGHOST"),
            PgUser = Env("PGUSER"),
            PgDatabase = Env("PGDATABASE") ?? "blueboard",
            PgEntraAuth = Flag("PG_ENTRA_AUTH"),
            PgClientId = Env("PG_CLIENT_ID"),
            PgMigrateUser = Env("PG_MIGRATE_USER"),
            PgRuntimePrincipalId = Env("PG_RUNTIME_PRINCIPAL_ID"),
            MigrateDatabaseUrl = Env("DATABASE_MIGRATE_URL"),
            TenantId = Env("AZURE_TENANT_ID"),
            ApiAudience = Env("BOARD_API_AUDIENCE"),
            ApiClientId = Env("BOARD_API_CLIENT_ID"),
            DevAuth = Flag("DEV_AUTH"),
            IngestEnabled = Flag("INGEST_ENABLED"),
            IngestLookbackHours = Int("INGEST_LOOKBACK_HOURS", 24),
            BrokerExecute = Flag("BROKER_EXECUTE"),
            PolicyFile = ResolvePath(Env("BLUEBOARD_POLICY_FILE")),
            PolicyJson = Env("BLUEBOARD_POLICY_JSON"),
            PurviewGuardMode = (Env("PURVIEW_CONTENT_GUARD") ?? "off").Trim().ToLowerInvariant(),
            ClaimLeaseSeconds = Int("CLAIM_LEASE_SECONDS", 600),
            DemoMode = Flag("DEMO_MODE"),
            GraphBaseUrl = Env("GRAPH_BASE_URL"),
            DefenderBaseUrl = Env("DEFENDER_BASE_URL"),
            WebhookAllowedHosts = (Env("WEBHOOK_ALLOWED_HOSTS") ?? "")
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(h => h.ToLowerInvariant()).ToArray(),
            WebhookSigningKey = Env("WEBHOOK_SIGNING_KEY"),
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
            PlaybooksDir = Env("BLUEBOARD_PLAYBOOKS_DIR") ?? Path.Combine(AppContext.BaseDirectory, "playbooks"),
            Ti = TiSettings.From(Env, Env("WEBSITE_INSTANCE_ID") is not null),
        };
        // WEBSITE_INSTANCE_ID / WEBSITE_SITE_NAME are set on every Azure Functions host, and AZURE_TENANT_ID means a
        // real tenant is configured: never allow dev auth or the demo in either case.
        var inAzure = Env("WEBSITE_INSTANCE_ID") is not null || Env("WEBSITE_SITE_NAME") is not null || s.TenantId is not null;
        if (s.DevAuth && inAzure) throw new InvalidOperationException("DEV_AUTH must not be enabled in Azure");
        if (s.DemoMode && inAzure) throw new InvalidOperationException("DEMO_MODE must not be enabled in Azure");
        if (s.DemoMode && !s.DevAuth) throw new InvalidOperationException("DEMO_MODE needs DEV_AUTH=true (local demo only)");
        if ((s.GraphBaseUrl ?? s.DefenderBaseUrl) is not null && !s.DemoMode)
            throw new InvalidOperationException("GRAPH_BASE_URL / DEFENDER_BASE_URL are only allowed with DEMO_MODE=true and DEV_AUTH=true");
        if (s.WebhookSigningKey is { } key && (!IsBase64(key, out var bytes) || bytes < 32))
            throw new InvalidOperationException("WEBHOOK_SIGNING_KEY must be base64 of at least 32 random bytes");
        if (s.PurviewGuardMode is not ("off" or "audit" or "block"))
            throw new InvalidOperationException("PURVIEW_CONTENT_GUARD must be off, audit or block");
        return s;
    }

    private static bool IsBase64(string s, out int bytes)
    {
        var buf = new byte[s.Length];
        var ok = Convert.TryFromBase64String(s, buf, out bytes);
        return ok;
    }

    /// <summary>
    /// A relative BLUEBOARD_POLICY_FILE is tried against the working directory, then the project folder above bin/, so
    /// the example local.settings.json works whether func starts from the project or from its output folder.
    /// </summary>
    internal static string? ResolvePath(string? path)
    {
        if (path is null || Path.IsPathRooted(path) || File.Exists(path)) return path;
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.GetFullPath(Path.Combine(dir.FullName, path));
            if (File.Exists(candidate)) return candidate;
            if (dir.Name == "bin") return Path.GetFullPath(Path.Combine(dir.Parent!.FullName, path));
        }
        return path;
    }
}
