namespace Blueboard.Api.Core;

/// <summary>
/// Okta, ServiceNow and Jira connectors (docs/INTEGRATIONS.md § Okta and § Ticketing). Every connector is off unless its
/// base URL is set. Credentials are app settings that are Key Vault references in the production profile; they are never
/// logged, returned by the API or shown to agents. Host names are checked here, once, so a typo fails start-up.
/// </summary>
public sealed record ConnectorSettings
{
    public OktaSettings Okta { get; init; } = new();
    public ServiceNowSettings ServiceNow { get; init; } = new();
    public JiraSettings Jira { get; init; } = new();
    public TicketRules Tickets { get; init; } = new();

    /// <summary>Local demo only (DEMO_MODE + DEV_AUTH): connector URLs may point at the mock API over plain http, and no credential is sent.</summary>
    public bool Mocked { get; init; }

    public bool AnyTicketing => ServiceNow.Enabled || Jira.Enabled;

    public static readonly string[] OktaHostSuffixes = [".okta.com", ".oktapreview.com"];
    public static readonly string[] ServiceNowHostSuffixes = [".service-now.com", ".servicenowservices.com"];
    public static readonly string[] JiraHostSuffixes = [".atlassian.net"];
    public static readonly string[] KeyVaultHostSuffixes = [".vault.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net"];
    public static readonly string[] Severities = ["informational", "low", "medium", "high"];
    public static readonly string[] SyncEvents = ["verdict", "action_result", "resolved"];
    public const int MinWebhookSecretLength = 32;

    public static ConnectorSettings From(Func<string, string?> env, Func<string, string[]> list, bool demo)
    {
        bool Flag(string k, bool d = false) => env(k) is { } v ? v is "true" or "1" or "True" : d;

        var okta = new OktaSettings();
        if (env("OKTA_ORG_URL") is { } oktaUrl)
        {
            var custom = env("OKTA_CUSTOM_DOMAIN")?.Trim().ToLowerInvariant().TrimEnd('.');
            var origin = Origin(oktaUrl, "OKTA_ORG_URL", OktaHostSuffixes, custom, demo);
            var mode = (env("OKTA_AUTH_MODE") ?? "private_key_jwt").Trim().ToLowerInvariant();
            if (mode is not ("private_key_jwt" or "ssws")) throw new InvalidOperationException("OKTA_AUTH_MODE must be private_key_jwt or ssws");
            okta = new OktaSettings
            {
                OrgUrl = origin,
                AuthMode = mode,
                ClientId = env("OKTA_CLIENT_ID"),
                SigningKeyUrl = env("OKTA_SIGNING_KEY_URL"),
                JwkKid = env("OKTA_JWK_KID"),
                ApiToken = env("OKTA_API_TOKEN"),
                Scopes = env("OKTA_SCOPES") ?? OktaSettings.DefaultScopes,
                EnrichIncidents = Flag("OKTA_ENRICH_INCIDENTS", true),
            };
            if (!demo)
            {
                if (mode == "private_key_jwt")
                {
                    if (okta.ClientId is null || okta.SigningKeyUrl is null)
                        throw new InvalidOperationException("OKTA_AUTH_MODE=private_key_jwt needs OKTA_CLIENT_ID and OKTA_SIGNING_KEY_URL (a Key Vault key)");
                    CheckKeyVaultKeyUrl(okta.SigningKeyUrl);
                }
                else if (okta.ApiToken is null) throw new InvalidOperationException("OKTA_AUTH_MODE=ssws needs OKTA_API_TOKEN (a Key Vault reference)");
            }
        }

        var sn = new ServiceNowSettings();
        if (env("SERVICENOW_INSTANCE_URL") is { } snUrl)
        {
            sn = new ServiceNowSettings
            {
                InstanceUrl = Origin(snUrl, "SERVICENOW_INSTANCE_URL", ServiceNowHostSuffixes, null, demo),
                ClientId = env("SERVICENOW_CLIENT_ID"),
                ClientSecret = env("SERVICENOW_CLIENT_SECRET"),
                Table = env("SERVICENOW_TABLE") ?? "incident",
                AssignmentGroup = env("SERVICENOW_ASSIGNMENT_GROUP"),
                ResolveState = env("SERVICENOW_RESOLVE_STATE"),
                CloseCode = env("SERVICENOW_CLOSE_CODE"),
                WebhookSecret = Secret(env("SERVICENOW_WEBHOOK_SECRET"), "SERVICENOW_WEBHOOK_SECRET"),
            };
            if (!System.Text.RegularExpressions.Regex.IsMatch(sn.Table, "^[a-z][a-z0-9_]{1,79}$"))
                throw new InvalidOperationException("SERVICENOW_TABLE must be a table name such as incident or sn_si_incident");
            if (!demo && (sn.ClientId is null || sn.ClientSecret is null))
                throw new InvalidOperationException("SERVICENOW_INSTANCE_URL needs SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET (OAuth client credentials)");
        }

        var jira = new JiraSettings();
        if (env("JIRA_BASE_URL") is { } jiraUrl)
        {
            jira = new JiraSettings
            {
                BaseUrl = Origin(jiraUrl, "JIRA_BASE_URL", JiraHostSuffixes, null, demo),
                Email = env("JIRA_EMAIL"),
                ApiToken = env("JIRA_API_TOKEN"),
                ProjectKey = env("JIRA_PROJECT_KEY") ?? "",
                IssueType = env("JIRA_ISSUE_TYPE") ?? "Task",
                ResolveTransitionId = env("JIRA_RESOLVE_TRANSITION_ID"),
                WebhookSecret = Secret(env("JIRA_WEBHOOK_SECRET"), "JIRA_WEBHOOK_SECRET"),
            };
            if (!System.Text.RegularExpressions.Regex.IsMatch(jira.ProjectKey, "^[A-Z][A-Z0-9_]{1,19}$"))
                throw new InvalidOperationException("JIRA_BASE_URL needs JIRA_PROJECT_KEY (e.g. SOC)");
            if (jira.ResolveTransitionId is { } tid && !tid.All(char.IsAsciiDigit))
                throw new InvalidOperationException("JIRA_RESOLVE_TRANSITION_ID must be a numeric transition id");
            if (!demo && (jira.Email is null || jira.ApiToken is null))
                throw new InvalidOperationException("JIRA_BASE_URL needs JIRA_EMAIL and JIRA_API_TOKEN");
        }

        var minSeverity = (env("TICKET_MIN_SEVERITY") ?? "high").Trim().ToLowerInvariant();
        if (minSeverity != "off" && !Severities.Contains(minSeverity))
            throw new InvalidOperationException("TICKET_MIN_SEVERITY must be off, informational, low, medium or high");
        var events = env("TICKET_SYNC_EVENTS") is null ? SyncEvents : list("TICKET_SYNC_EVENTS").Select(e => e.ToLowerInvariant()).Distinct().ToArray();
        if (events.FirstOrDefault(e => !SyncEvents.Contains(e)) is { } bad)
            throw new InvalidOperationException($"TICKET_SYNC_EVENTS: unknown event {bad} (use {string.Join(", ", SyncEvents)})");

        return new ConnectorSettings
        {
            Okta = okta,
            ServiceNow = sn,
            Jira = jira,
            Tickets = new TicketRules
            {
                MinSeverity = minSeverity,
                OnPlaybook = Flag("TICKET_ON_PLAYBOOK"),
                OnActionApproved = Flag("TICKET_ON_ACTION_APPROVED"),
                SyncEvents = events,
            },
            Mocked = demo,
        };
    }

    /// <summary>
    /// An https origin (no path, query, credentials or port other than 443) whose host ends with one of the vendor's
    /// suffixes or equals the configured custom domain. Demo mode also accepts plain http to the mock API.
    /// </summary>
    internal static string Origin(string url, string name, string[] suffixes, string? customHost, bool demo)
    {
        if (!Uri.TryCreate(url.Trim().TrimEnd('/'), UriKind.Absolute, out var u) || u.UserInfo.Length > 0 || u.Query.Length > 0 || u.Fragment.Length > 0
            || u.AbsolutePath != "/")
            throw new InvalidOperationException($"{name} must be an origin such as https://example{suffixes[0]} (no path, query or credentials)");
        if (demo && u.Scheme is "http" or "https") return u.GetLeftPart(UriPartial.Authority);
        if (u.Scheme != Uri.UriSchemeHttps || !u.IsDefaultPort) throw new InvalidOperationException($"{name} must use https on port 443");
        var host = u.IdnHost.ToLowerInvariant().TrimEnd('.');
        var ok = suffixes.Any(s => host.EndsWith(s, StringComparison.Ordinal) && host.Length > s.Length && !host[..^s.Length].Contains('/'))
                 || (customHost is { Length: > 0 } && host == customHost);
        if (!ok) throw new InvalidOperationException($"{name} host {host} is not allowed: it must end with {string.Join(" or ", suffixes)}{(name == "OKTA_ORG_URL" ? " or equal OKTA_CUSTOM_DOMAIN" : "")}");
        return u.GetLeftPart(UriPartial.Authority);
    }

    /// <summary>A Key Vault key identifier: https://{vault}.vault.azure.net/keys/{name}[/{version}].</summary>
    internal static void CheckKeyVaultKeyUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps || u.UserInfo.Length > 0 || u.Query.Length > 0
            || !KeyVaultHostSuffixes.Any(s => u.Host.EndsWith(s, StringComparison.OrdinalIgnoreCase))
            || !System.Text.RegularExpressions.Regex.IsMatch(u.AbsolutePath, "^/keys/[A-Za-z0-9-]{1,127}(/[0-9a-f]{32})?$"))
            throw new InvalidOperationException("OKTA_SIGNING_KEY_URL must be a Key Vault key id, e.g. https://kv-x.vault.azure.net/keys/okta-signing/<version>");
    }

    private static string? Secret(string? value, string name) =>
        value is null ? null
        : value.Length >= MinWebhookSecretLength ? value
        : throw new InvalidOperationException($"{name} must be at least {MinWebhookSecretLength} characters (random)");
}

public sealed record OktaSettings
{
    /// <summary>
    /// The least the connector needs. okta.users.read: users, factors, groups. okta.logs.read: System Log.
    /// okta.roles.read: admin roles on lookups (optional; without it lookups say not_checked). okta.users.manage:
    /// suspend, unsuspend, reset factors and DELETE /users/{id}/sessions. okta.sessions.manage is not needed.
    /// </summary>
    public const string DefaultScopes = "okta.users.read okta.logs.read okta.roles.read okta.users.manage";

    public string? OrgUrl { get; init; }
    /// <summary>private_key_jwt (preferred: the key never leaves Key Vault) or ssws (an API token: less preferred).</summary>
    public string AuthMode { get; init; } = "private_key_jwt";
    public string? ClientId { get; init; }
    /// <summary>Key Vault key id of the RSA key the client assertion is signed with (Key Vault signs; the key is not exportable).</summary>
    public string? SigningKeyUrl { get; init; }
    /// <summary>The kid of the public key registered on the Okta service app (JWT header). Optional.</summary>
    public string? JwkKid { get; init; }
    /// <summary>SSWS fallback. A secret: never logged or returned.</summary>
    public string? ApiToken { get; init; }
    public string Scopes { get; init; } = DefaultScopes;
    public bool EnrichIncidents { get; init; } = true;
    public bool Enabled => OrgUrl is not null;
}

public sealed record ServiceNowSettings
{
    public string? InstanceUrl { get; init; }
    public string? ClientId { get; init; }
    /// <summary>OAuth client secret. A secret: never logged or returned.</summary>
    public string? ClientSecret { get; init; }
    public string Table { get; init; } = "incident";
    public string? AssignmentGroup { get; init; }
    /// <summary>State value to set when the board incident resolves (e.g. 6). Unset: a work note only.</summary>
    public string? ResolveState { get; init; }
    public string? CloseCode { get; init; }
    /// <summary>Shared secret for signed inbound updates (HMAC-SHA256). Unset: inbound is off.</summary>
    public string? WebhookSecret { get; init; }
    public bool Enabled => InstanceUrl is not null;
}

public sealed record JiraSettings
{
    public string? BaseUrl { get; init; }
    public string? Email { get; init; }
    /// <summary>Atlassian API token for the integration account. A secret: never logged or returned.</summary>
    public string? ApiToken { get; init; }
    public string ProjectKey { get; init; } = "";
    public string IssueType { get; init; } = "Task";
    public string? ResolveTransitionId { get; init; }
    /// <summary>Webhook secret (Jira admin webhooks sign with X-Hub-Signature). Unset: inbound is off.</summary>
    public string? WebhookSecret { get; init; }
    public bool Enabled => BaseUrl is not null;
}

/// <summary>When the board opens a ticket for an incident, and which board events it writes back to the ticket.</summary>
public sealed record TicketRules
{
    /// <summary>off, or the lowest incident severity that opens a ticket.</summary>
    public string MinSeverity { get; init; } = "high";
    public bool OnPlaybook { get; init; }
    public bool OnActionApproved { get; init; }
    public string[] SyncEvents { get; init; } = ConnectorSettings.SyncEvents;

    public bool SeverityQualifies(string? severity)
    {
        if (MinSeverity == "off") return false;
        var have = Array.IndexOf(ConnectorSettings.Severities, (severity ?? "").ToLowerInvariant());
        return have >= 0 && have >= Array.IndexOf(ConnectorSettings.Severities, MinSeverity);
    }
}
