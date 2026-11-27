using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Ops;

/// <summary>One enterprise control: whether this deployment enforces it, why it matters, and how to turn it on.</summary>
public sealed record PostureControl(
    string Id, string Area, string Title, string State, int Weight, string Detail, string? Fix, string? Owner, string? Threat);

public sealed record PostureReport(DateTimeOffset CheckedAt, int Score, int MaxScore, IReadOnlyList<PostureControl> Controls);

/// <summary>
/// Admin → Posture: the enterprise controls this deployment has on, scored like Microsoft Secure Score (each control
/// carries a weight; "met" earns it, "partial" half, "not_met" none, "external" is the consumer's to confirm and isn't
/// scored). Built only from settings and the database: no Microsoft calls, so it's cheap and can't leak anything.
/// External controls (Conditional Access enforcement, PIM) live in Entra and the board can't see them: they're listed
/// so the checklist is complete, with the script or portal step that does them.
/// </summary>
public sealed class Posture(Db db, Settings settings, Policy policy)
{
    public const string Met = "met", Partial = "partial", NotMet = "not_met", External = "external";

    public async Task<PostureReport> BuildAsync(Principal me, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        int approvers = 0, admins = 0, staleAgents = 0;
        await using (var cmd = db.Command("""
            select count(*) filter (where kind = 'human' and 'approver' = any(roles))::int,
                   count(*) filter (where kind = 'human' and 'admin' = any(roles))::int,
                   count(*) filter (where kind = 'agent' and coalesce(last_seen_at, created_at) < now() - interval '30 days')::int
            from principals where enabled
            """))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            if (await r.ReadAsync(ct)) { approvers = r.GetInt32(0); admins = r.GetInt32(1); staleAgents = r.GetInt32(2); }
        return Score(Controls(settings, policy, approvers, admins, staleAgents, Environment.GetEnvironmentVariable));
    }

    internal static PostureReport Score(IReadOnlyList<PostureControl> controls)
    {
        var scored = controls.Where(c => c.State != External).ToList();
        var max = scored.Sum(c => c.Weight);
        var score = scored.Sum(c => c.State == Met ? c.Weight : c.State == Partial ? c.Weight / 2 : 0);
        return new PostureReport(DateTimeOffset.UtcNow, score, max, controls);
    }

    internal static IReadOnlyList<PostureControl> Controls(Settings s, Policy p, int approvers, int admins, int staleAgents, Func<string, string?> env)
    {
        var profile = env("BOARD_PROFILE") ?? "unknown";
        var edge = env("BOARD_EDGE") ?? "none";
        var pgSsl = (env("PG_SSL_MODE") ?? "").Trim().ToLowerInvariant();
        var prod = profile == "production";
        var auditConfigured = s.AuditDceEndpoint is not null && s.AuditDcrId is not null;
        var verifiedDb = s.DatabaseUrl is null && (pgSsl is "" or "verifyfull" or "verify-full");
        var wafBlocking = edge == "front_door_waf" && env("BOARD_WAF_MODE") == "Prevention";
        var protectedCount = p.ProtectedUsers.Length + p.ProtectedDevices.Length + p.ProtectedApps.Length + p.ProtectedIndicators.Length;
        var list = new List<PostureControl>
        {
            // Identity and access
            new("sso", "Identity", "Single sign-on with Microsoft Entra ID", s.DevAuth ? NotMet : s.TenantId is null ? NotMet : Met, 10,
                s.DevAuth ? "DEV_AUTH is on: identities are not verified." : s.TenantId is null ? "Entra tenant is not configured." : "Entra tokens validated on every request (issuer, audience, tenant, signature, scope, client).",
                s.DevAuth ? "Local development only. Never deploy with DEV_AUTH." : s.TenantId is null ? "Configure AZURE_TENANT_ID and the board app registration." : null, "blueboard", "TM-15"),
            new("sod", "Identity", "Separation of duties: two or more approvers", approvers >= 2 ? Met : approvers == 1 ? Partial : NotMet, 10,
                $"{approvers} enabled approver(s), {admins} admin(s). Requesters can never approve their own actions.",
                approvers >= 2 ? null : "Add people to the approvers group (infra/entra-groups.sh).", "consumer", "TM-08"),
            new("mfa", "Identity", "Phishing-resistant MFA and compliant devices (Conditional Access)", External, 10,
                "Enforced in Entra, not visible to the board. conditional-access.sh creates the baseline in report-only mode.",
                "BB_ENV=<env> CA_APPLY=1 CA_STATE=on ./infra/conditional-access.sh after a report-only review.", "consumer", "TM-28"),
            new("pim", "Identity", "Just-in-time approvers and admins (PIM for Groups)", External, 5,
                "Configured in Entra ID Governance.", "Make the approvers and admins groups PIM-eligible (docs/ENTERPRISE-ACCESS.md).", "consumer", null),
            new("idle", "Identity", "Idle session sign-out", s.SessionIdleMinutes is > 0 and <= 15 ? Met : s.SessionIdleMinutes > 0 ? Partial : NotMet, 5,
                s.SessionIdleMinutes > 0 ? $"Browser sessions end after {s.SessionIdleMinutes} idle minutes." : "Off: browser sessions stay signed in while the tab is open.",
                s.SessionIdleMinutes is > 0 and <= 15 ? null : "SESSION_IDLE_MINUTES=15 ./infra/deploy.sh", "blueboard", "TM-29"),
            new("inactive", "Identity", "Inactive accounts disabled automatically", s.InactiveDisableDays is > 0 and <= 45 ? Met : s.InactiveDisableDays > 0 ? Partial : NotMet, 5,
                s.InactiveDisableDays > 0 ? $"Principals not seen for {s.InactiveDisableDays} days are disabled daily. {staleAgents} agent(s) idle over 30 days." : $"Off. {staleAgents} enabled agent(s) idle over 30 days.",
                s.InactiveDisableDays is > 0 and <= 45 ? null : "INACTIVE_DISABLE_DAYS=45 ./infra/deploy.sh", "blueboard", "TM-41"),

            // Containment safety
            new("policy", "Containment", "Protected assets in the action policy", p.Missing ? NotMet : protectedCount > 0 ? Met : NotMet, 10,
                p.Missing ? "A policy is configured but its file wasn't found: the built-in default is in force." : $"{protectedCount} protected user, device, app and indicator entries.",
                protectedCount > 0 && !p.Missing ? null : "Fill in policy.json protected_* lists (templates/policies/) and redeploy.", "consumer", "TM-04"),
            new("two_approvers", "Containment", "Two approvers for the highest-impact actions", p.RequireTwoApprovers.Length > 0 ? Met : NotMet, 5,
                p.RequireTwoApprovers.Length > 0 ? $"Required for: {string.Join(", ", p.RequireTwoApprovers)}." : "Every action needs one approver.",
                p.RequireTwoApprovers.Length > 0 ? null : "Add disable_user, purge_email, disable_service_principal to require_two_approvers.", "consumer", "TM-08"),

            // Data protection
            new("network", "Data protection", "Private networking for data services", prod ? Met : NotMet, 10,
                prod ? "Production profile declares private endpoints for PostgreSQL, Storage and Key Vault. Verify deployed networking in Azure." : "Production networking is not declared. The mvp template uses a public PostgreSQL endpoint with AllowAzureServices.",
                prod ? null : "BB_PROFILE=production ./infra/up.sh for real incident data.", "consumer", "TM-35"),
            new("pg_tls", "Data protection", "Database connections verify the server certificate", verifiedDb ? Met : s.DatabaseUrl is null && (pgSsl is "verifyca" or "verify-ca") ? Partial : NotMet, 5,
                s.DatabaseUrl is not null ? "DATABASE_URL uses local-development TLS settings; server certificate verification is not enforced." : verifiedDb ? "PGHOST connections require certificate and host name verification (VerifyFull)." : $"PG_SSL_MODE={env("PG_SSL_MODE")}: server identity is not fully verified.",
                verifiedDb ? null : "Use PGHOST settings and remove PG_SSL_MODE (defaults to VerifyFull).", "blueboard", "TM-33"),
            new("secrets", "Data protection", "Secrets in Key Vault", prod ? Met : NotMet, 5,
                prod ? "Production profile declares Key Vault references. Verify the deployed app settings in Azure." : "mvp profile: optional secrets are plain app settings.",
                prod ? null : "Use the production profile.", "consumer", "TM-35"),
            new("retention", "Data protection", "Data retention period set", s.RetentionDays > 0 ? Met : NotMet, 5,
                s.RetentionDays > 0 ? $"Resolved records older than {s.RetentionDays} days are removed daily; audit_log is kept." : "Off: incidents, messages and actions are kept forever.",
                s.RetentionDays > 0 ? null : "RETENTION_DAYS=<days> ./infra/deploy.sh (preview first: blueboard retention --days N).", "consumer", "TM-37"),
            new("edge", "Data protection", "Web application firewall in front of the board", wafBlocking ? Met : edge == "front_door_waf" ? Partial : NotMet, 5,
                edge == "front_door_waf" ? (wafBlocking ? "Front Door WAF is configured in Prevention mode. Verify origin lockdown and WAF logs in Azure." : "Front Door is configured, but blocking mode is not confirmed. Detection mode logs without blocking.") : "No WAF: the apps are reached directly (token auth on every API call).",
                wafBlocking ? null : "After tuning in Detection: FRONT_DOOR=true WAF_MODE=Prevention ./infra/deploy.sh.", "consumer", "TM-36"),

            new("connector_secrets", "Data protection", "Connector credentials are non-exportable or in Key Vault",
                !(s.Connectors.Okta.Enabled || s.Connectors.AnyTicketing) ? Met
                : s.Connectors.Okta.Enabled && s.Connectors.Okta.AuthMode == "ssws" ? Partial
                : prod ? Met : Partial, 5,
                !(s.Connectors.Okta.Enabled || s.Connectors.AnyTicketing) ? "No third-party connector is configured."
                : $"Okta: {(s.Connectors.Okta.Enabled ? s.Connectors.Okta.AuthMode : "off")}. Ticketing: {(s.Connectors.AnyTicketing ? (prod ? "Key Vault references" : "plain app settings (mvp)") : "off")}.",
                s.Connectors.Okta.Enabled && s.Connectors.Okta.AuthMode == "ssws" ? "Move Okta to OKTA_AUTH_MODE=private_key_jwt with a Key Vault key (docs/INTEGRATIONS.md § Okta)."
                : (s.Connectors.Okta.Enabled || s.Connectors.AnyTicketing) && !prod ? "Use the production profile so connector secrets are Key Vault references." : null,
                "consumer", "TM-45"),

            // Monitoring
            new("audit_export", "Monitoring", "Audit export configured for Microsoft Sentinel", auditConfigured ? Met : NotMet, 10,
                auditConfigured ? "Export endpoint and rule are configured. Confirm recent rows arrive in BlueboardAudit_CL; configuration does not prove delivery." : "Audit export requires both a collection endpoint and a rule ID. The database owner could alter local audit rows.",
                auditConfigured ? null : "Use the production profile; check AUDIT_DCE_ENDPOINT and AUDIT_DCR_ID.", "consumer", "TM-24"),
            new("notify", "Monitoring", "Approvers are notified outside the board",
                s.NotifyTeamsWebhookUrl is not null || s.NotifyWebhookUrl is not null || s.NotifyMailFrom is not null || s.NotifyNtfyUrl is not null ? Met : NotMet, 5,
                "A notification sink is configured when this control is met. Send a test from Setup and verify receipt.",
                "Configure a sink (docs/OPERATIONS.md § Notifications).", "consumer", null),

            // Change control
            new("dry_run", "Change control", "Broker execution mode", Met, 0,
                s.BrokerExecute ? "Live: approved actions run against the tenant." : "Dry run: approved actions are recorded, never sent. Safe, but containment doesn't happen.",
                null, "consumer", null),
        };
        return list;
    }
}
