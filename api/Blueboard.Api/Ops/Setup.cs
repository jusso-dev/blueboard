using System.Globalization;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;

namespace Blueboard.Api.Ops;

public static class CheckStatus
{
    public const string Ok = "ok";
    public const string Warning = "warning";
    public const string Failed = "failed";
}

/// <summary>One line on the setup page / in `blueboard doctor`. Status is always a word, Fix names the script or setting.</summary>
public sealed record Check(string Id, string Name, string Status, string Detail, string? Fix = null, IReadOnlyList<string>? Lines = null);

public sealed record SetupReport(DateTimeOffset CheckedAt, bool Ok, IReadOnlyList<Check> Checks);

/// <summary>What the shell banner needs on every page: cheap, no Microsoft calls.</summary>
public sealed record BoardStatus(string Broker, string? PausedBy, DateTimeOffset? PausedAt, string Policy, int Held);

/// <summary>
/// The setup checklist (issue #2): is the board ready, in plain words, with what to do next for each failing line.
/// Shared by GET /api/setup and `blueboard doctor`. Microsoft checks are harmless reads only (GETs plus one
/// runHuntingQuery POST); write permissions are read from the managed identity token's roles claim, never by
/// calling a write endpoint. Results never include tokens, URLs with secrets or policy contents beyond counts.
/// </summary>
public sealed class Setup(Db db, Settings settings, Policy policy, MsClient ms, Notifier notifier)
{
    private static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(15);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SetupReport? _cached;

    /// <summary>The report, cached for 60 seconds so the page can't be used to hammer Graph.</summary>
    public async Task<SetupReport> GetAsync(CancellationToken ct = default)
    {
        if (_cached is { } c && DateTimeOffset.UtcNow - c.CheckedAt < CacheFor) return c;
        await _gate.WaitAsync(ct);
        try
        {
            if (_cached is { } c2 && DateTimeOffset.UtcNow - c2.CheckedAt < CacheFor) return c2;
            return _cached = await RunAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public void Invalidate() => _cached = null;

    public async Task<SetupReport> RunAsync(CancellationToken ct = default)
    {
        var checks = new List<Check> { await DatabaseAsync(ct), Auth(), await IngestAsync(ct) };
        checks.AddRange(await MicrosoftAsync(ct));
        checks.Add(await BrokerAsync(ct));
        checks.Add(PolicyCheck());
        checks.Add(await AgentsAsync(ct));
        checks.Add(await NotificationsAsync(ct));
        checks.Add(await AuditExportAsync(ct));
        return new SetupReport(DateTimeOffset.UtcNow, checks.All(c => c.Status != CheckStatus.Failed), checks);
    }

    // 1. database ----------------------------------------------------------------------------------
    private async Task<Check> DatabaseAsync(CancellationToken ct)
    {
        const string name = "Database";
        try
        {
            var applied = new HashSet<string>();
            await using (var cmd = db.Command("select name from schema_migrations"))
            await using (var r = await cmd.ExecuteReaderAsync(ct))
                while (await r.ReadAsync(ct)) applied.Add(r.GetString(0));
            var dir = Path.Combine(AppContext.BaseDirectory, "migrations");
            var files = Directory.Exists(dir) ? Directory.GetFiles(dir, "*.sql").Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal).ToList() : [];
            var pending = files.Where(f => !applied.Contains(f)).ToList();
            if (files.Count == 0) return new("database", name, CheckStatus.Warning, "Reachable, but no migration files ship with this build, so currency can't be checked.");
            return pending.Count == 0
                ? new("database", name, CheckStatus.Ok, $"Reachable. All {files.Count} migrations applied.")
                : new("database", name, CheckStatus.Failed, $"Reachable, but {pending.Count} migration(s) not applied: {string.Join(", ", pending)}.",
                    "Restart the Function App (migrations run at start-up) or run `blueboard migrate`, then check Application Insights for 'database migration failed'.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return new("database", name, CheckStatus.Failed, $"Not reachable ({ex.GetType().Name}).",
                "Check PGHOST / DATABASE_URL, the PostgreSQL firewall or private endpoint, and that the board identity is the server's Entra admin (infra/main.bicep).");
        }
    }

    // 2. auth --------------------------------------------------------------------------------------
    private Check Auth()
    {
        const string name = "Sign-in";
        if (settings.DevAuth)
            return new("auth", name, CheckStatus.Warning, "DEV_AUTH is on: anyone who can reach the API can pick an identity. Local development only (refused in Azure).",
                "Unset DEV_AUTH everywhere except your own machine.");
        if (settings.TenantId is null || settings.ApiAudience is null)
            return new("auth", name, CheckStatus.Failed, "Entra bearer tokens can't be validated: AZURE_TENANT_ID or BOARD_API_AUDIENCE is not set.",
                "Run ./infra/entra-app.sh, then redeploy with ./infra/deploy.sh (it sets both).");
        return new("auth", name, CheckStatus.Ok, $"Entra bearer tokens for {settings.ApiAudience} (people with the Board.Access scope, agents app-only).");
    }

    // 3. ingest ------------------------------------------------------------------------------------
    public sealed record IngestRun(DateTimeOffset At, int Fetched = 0, string? Error = null);

    private async Task<Check> IngestAsync(CancellationToken ct)
    {
        const string name = "Incident ingest";
        var kv = new KvState(db);
        IngestRun? ok = null, err = null;
        try
        {
            ok = await kv.GetAsync<IngestRun>(KvState.IngestLastSuccess, ct);
            err = await kv.GetAsync<IngestRun>(KvState.IngestLastError, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested) { /* the database check reports it */ }
        if (!settings.IngestEnabled)
            return new("ingest", name, CheckStatus.Warning, "Off (INGEST_ENABLED is not true): no incidents are posted from Defender.",
                "Redeploy with INGEST_ENABLED=true (the default for ./infra/deploy.sh).");
        if (err is not null && (ok is null || err.At > ok.At))
            return new("ingest", name, CheckStatus.Failed, $"Last run failed {Ago(err.At)}: {err.Error}",
                "Check SecurityIncident.Read.All and SecurityAlert.Read.All on the board identity (./infra/grant-permissions.sh).");
        if (ok is null)
            return new("ingest", name, CheckStatus.Warning, "On, but no successful run yet (it runs every minute).", "Wait a minute and reload; if it stays empty, check Application Insights for the ingest-incidents function.");
        if (DateTimeOffset.UtcNow - ok.At > TimeSpan.FromMinutes(10))
            return new("ingest", name, CheckStatus.Warning, $"Last successful run {Ago(ok.At)}: it should run every minute.", "Check that the Function App is running and its timer triggers are enabled.");
        return new("ingest", name, CheckStatus.Ok, $"Last successful run {Ago(ok.At)} ({ok.Fetched} incident(s) fetched).");
    }

    // 4 + 5. Microsoft reads and write permissions ---------------------------------------------------
    /// <summary>Harmless read probes, then write permissions from the token's roles claim. Public for the no-write test.</summary>
    public async Task<IReadOnlyList<Check>> MicrosoftAsync(CancellationToken ct = default)
    {
        if (settings.DevAuth)
            return
            [
                new("reads", "Read permissions", CheckStatus.Warning, "Skipped in local development (DEV_AUTH): the probes would run as your own Azure sign-in, not the board's identity."),
                new("writes", "Write permissions", CheckStatus.Warning, "Skipped in local development (DEV_AUTH)."),
            ];
        return [await ReadsAsync(ct), await WritesAsync(ct)];
    }

    private static readonly (string Label, MsApi Api, string Path, string Permission)[] Probes =
    [
        ("List 1 incident", MsApi.Graph, "/v1.0/security/incidents?$top=1&$select=id", "SecurityIncident.Read.All"),
        ("Hunting query DeviceInfo | take 1", MsApi.Graph, "/v1.0/security/runHuntingQuery", "ThreatHunting.Read.All"),
        ("Read 1 user", MsApi.Graph, "/v1.0/users?$top=1&$select=id", "User.Read.All"),
        ("List 1 machine", MsApi.Defender, "/api/machines?$top=1", "Machine.Read.All"),
    ];

    private async Task<Check> ReadsAsync(CancellationToken ct)
    {
        var lines = new List<string>();
        var missing = new List<string>();
        foreach (var (label, api, path, perm) in Probes)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(ProbeTimeout);
            try
            {
                // runHuntingQuery is a POST, but KQL can't write: the one non-GET these checks make.
                if (path.EndsWith("/runHuntingQuery", StringComparison.Ordinal))
                    await ms.SendAsync(api, path, HttpMethod.Post, new { query = "DeviceInfo | take 1" }, timeout.Token);
                else
                    await ms.SendAsync(api, path, HttpMethod.Get, null, timeout.Token);
                lines.Add($"OK: {label} ({perm})");
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                missing.Add(perm);
                lines.Add($"Failed: {label}: {Short(ex)} (needs {perm})");
            }
        }
        return missing.Count == 0
            ? new("reads", "Read permissions", CheckStatus.Ok, "Every harmless read worked.", null, lines)
            : new("reads", "Read permissions", CheckStatus.Failed, $"{missing.Count} of {Probes.Length} reads failed: {string.Join(", ", missing)}.",
                "Run ./infra/grant-permissions.sh (Privileged Role Administrator), then restart the Function App so it gets a fresh token.", lines);
    }

    private async Task<Check> WritesAsync(CancellationToken ct)
    {
        const string name = "Write permissions";
        var roles = new Dictionary<MsApi, string[]>();
        foreach (var api in new[] { MsApi.Graph, MsApi.Defender })
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(ProbeTimeout);
            try { roles[api] = await ms.TokenRolesAsync(api, timeout.Token); }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                return new("writes", name, CheckStatus.Failed, $"Couldn't get a token for the board's managed identity ({ex.GetType().Name}).",
                    "Check AZURE_CLIENT_ID matches the Function App's user-assigned identity (infra/main.bicep).");
            }
        }
        var lines = new List<string>();
        var missing = new SortedSet<string>(StringComparer.Ordinal);
        var kinds = Catalog.All.Keys.Where(k => !policy.Disabled.Contains(k)).Order(StringComparer.Ordinal);
        foreach (var group in kinds.GroupBy(k => Permissions.WriteFor[k]))
        {
            var perm = group.Key;
            var has = roles[perm.Api].Contains(perm.Name);
            if (!has) missing.Add(perm.Name);
            lines.Add(has
                ? $"Granted: {perm.Name} ({perm.ApiName}) for {string.Join(", ", group)}"
                : $"Not granted: brokered actions will fail: {perm.Name} ({perm.ApiName}) for {string.Join(", ", group)}");
        }
        if (notifier.Sinks().Any(s => s.Sink == "mail"))
        {
            var has = roles[MsApi.Graph].Contains(Permissions.MailSend.Name);
            if (!has) missing.Add(Permissions.MailSend.Name);
            lines.Add(has ? "Granted: Mail.Send (Microsoft Graph) for approver email" : "Not granted: approver email will fail: Mail.Send (Microsoft Graph)");
        }
        if (missing.Count == 0) return new("writes", name, CheckStatus.Ok, "Every action the policy allows has its permission.", null, lines);
        // Missing writes with the broker live is a failure; in dry run (or READ_ONLY=1 on purpose) it's a warning.
        return new("writes", name, settings.BrokerExecute ? CheckStatus.Failed : CheckStatus.Warning,
            $"Not granted: brokered actions will fail: {string.Join(", ", missing)}.",
            "Run ACTIONS=\"<kinds>\" ./infra/grant-permissions.sh for the actions you broker (Privileged Role Administrator), or list unused kinds under \"disabled\" in policy.json.",
            lines);
    }

    // 6. broker ------------------------------------------------------------------------------------
    public async Task<BoardStatus> StatusAsync(CancellationToken ct = default)
    {
        var pause = await new KvState(db).GetAsync<BrokerPause>(KvState.BrokerPaused, ct);
        await using var cmd = db.Command("select count(*)::int from actions where status = 'approved' and held_at is not null");
        var held = (int)(await cmd.ExecuteScalarAsync(ct))!;
        var broker = pause?.Paused == true ? "paused" : settings.BrokerExecute ? "live" : "dry_run";
        return new BoardStatus(broker, pause?.Paused == true ? pause.By : null, pause?.Paused == true ? pause.At : null, PolicyState, held);
    }

    private string PolicyState => policy.Missing ? "missing" : policy.Source is null ? "default" : "loaded";

    private async Task<Check> BrokerAsync(CancellationToken ct)
    {
        const string name = "Broker";
        BoardStatus s;
        try { s = await StatusAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return new("broker", name, CheckStatus.Failed, "Couldn't read the broker state from the database.");
        }
        var held = s.Held > 0 ? $" {s.Held} approved action(s) are held, waiting for Run now." : "";
        return s.Broker switch
        {
            "paused" => new("broker", name, CheckStatus.Warning, $"Paused by @{s.PausedBy} {Ago(s.PausedAt!.Value)}: approved actions are held, nothing runs.{held}",
                "Resume it on Admin → Participants when it's safe."),
            "dry_run" => new("broker", name, CheckStatus.Warning, $"Dry run (BROKER_EXECUTE=false): approved actions are recorded but never sent to Defender or Entra.{held}",
                "When policy.json is reviewed and every action is tested in a non-production tenant, redeploy with BROKER_EXECUTE=true."),
            _ => new("broker", name, CheckStatus.Ok, $"Live: approved actions run against your tenant.{held}"),
        };
    }

    // 7. policy ------------------------------------------------------------------------------------
    private Check PolicyCheck()
    {
        const string name = "Policy";
        var counts = $"{policy.ProtectedUsers.Length} protected user(s), {policy.ProtectedDevices.Length} device(s), {policy.ProtectedIndicators.Length} indicator(s); "
                     + $"{policy.AutoApprove.Length} auto-approved kind(s), {policy.Disabled.Length} disabled.";
        if (policy.Missing)
            return new("policy", name, CheckStatus.Failed, $"A policy is configured but its file wasn't found, so the built-in default is in force. {counts}",
                "Check BLUEBOARD_POLICY_FILE, or redeploy with POLICY_FILE=policy.json ./infra/deploy.sh.");
        if (policy.Source is null)
            return new("policy", name, CheckStatus.Warning, $"Default policy (no policy file): nothing is protected. {counts}",
                "Write policy.json (see docs/SECURITY.md § Action policy) and redeploy with POLICY_FILE=policy.json ./infra/deploy.sh.");
        var empty = policy.ProtectedUsers.Length + policy.ProtectedDevices.Length + policy.ProtectedIndicators.Length == 0;
        return empty
            ? new("policy", name, CheckStatus.Warning, $"Loaded from {policy.Source}, but every protected list is empty. {counts}",
                "Add break-glass accounts, domain controllers and your own domains to policy.json.")
            : new("policy", name, CheckStatus.Ok, $"Loaded from {policy.Source}. {counts}");
    }

    // 8. agents ------------------------------------------------------------------------------------
    private async Task<Check> AgentsAsync(CancellationToken ct)
    {
        const string name = "Agents";
        var lines = new List<string>();
        DateTimeOffset? latest = null;
        try
        {
            await using var cmd = db.Command("select handle, last_seen_at, enabled from principals where kind = 'agent' order by last_seen_at desc nulls last limit 50");
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
            {
                var seen = r.Get<DateTimeOffset?>("last_seen_at");
                if (r.GetBoolean(2) && seen is { } s && (latest is null || s > latest)) latest = s;
                lines.Add($"@{r.GetString(0)}: {(seen is { } t ? $"last seen {Ago(t)}" : "never seen")}{(r.GetBoolean(2) ? "" : " (disabled)")}");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return new("agents", name, CheckStatus.Failed, "Couldn't read principals from the database.");
        }
        if (lines.Count == 0)
            return new("agents", name, CheckStatus.Warning, "No agent has signed in yet.",
                "Give each agent identity Board.Post, Board.Hunt, Board.RequestActions (./infra/assign-roles.sh) and point it at /runtime/webhooks/mcp.");
        if (latest is null || DateTimeOffset.UtcNow - latest > TimeSpan.FromMinutes(15))
            return new("agents", name, CheckStatus.Warning, $"No agent seen in the last 15 minutes ({lines.Count} known).",
                "Check the agents are running and their tokens are for the board API audience.", lines);
        return new("agents", name, CheckStatus.Ok, $"Last agent check-in {Ago(latest.Value)} ({lines.Count} known).", null, lines);
    }

    // notifications (#3) -----------------------------------------------------------------------------
    private async Task<Check> NotificationsAsync(CancellationToken ct)
    {
        const string name = "Approver notifications";
        var sinks = notifier.Sinks();
        if (sinks.Count == 0)
            return new("notify", name, CheckStatus.Warning, "Approvers are not notified: no Teams, email or webhook is configured.",
                "Set NOTIFY_TEAMS_WEBHOOK_URL, NOTIFY_MAIL_FROM + NOTIFY_MAIL_TO, or NOTIFY_WEBHOOK_URL (docs/OPERATIONS.md).");
        IReadOnlyDictionary<string, (string Status, DateTimeOffset At, string? Error)> last;
        try { last = await notifier.LastDeliveryAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested) { last = new Dictionary<string, (string, DateTimeOffset, string?)>(); }
        var lines = sinks.Select(s => s.Problem is { } p ? $"{s.Sink}: not usable: {p}"
            : last.TryGetValue(s.Sink, out var l) ? $"{s.Sink}: ready; last delivery {l.Status} {Ago(l.At)}{(l.Error is null ? "" : $" ({l.Error})")}"
            : $"{s.Sink}: ready; nothing sent yet").ToList();
        var broken = sinks.Where(s => s.Problem is not null).ToList();
        if (broken.Count > 0)
            return new("notify", name, CheckStatus.Failed, $"{broken.Count} sink(s) can't send: {string.Join(", ", broken.Select(b => b.Sink))}.",
                "Fix the settings named below (docs/OPERATIONS.md § Notifications), then use Send test notification.", lines);
        var failing = sinks.Where(s => last.TryGetValue(s.Sink, out var l) && l.Status == "failed").Select(s => s.Sink).ToList();
        if (failing.Count > 0)
            return new("notify", name, CheckStatus.Warning, $"Last delivery failed for {string.Join(", ", failing)}: approvers may not have been told.",
                "Check the receiving end (Teams workflow, mailbox, webhook receiver) and NOTIFY_ALLOWED_HOSTS, then use Send test notification.", lines);
        return new("notify", name, CheckStatus.Ok, $"{string.Join(", ", sinks.Select(s => s.Sink))}, reminders every {settings.NotifyRemindMinutes} minutes.", null, lines);
    }

    // audit export (#26) -------------------------------------------------------------------------------
    private async Task<Check> AuditExportAsync(CancellationToken ct)
    {
        const string name = "Audit export to Sentinel";
        if (settings.AuditDceEndpoint is null || settings.AuditDcrId is null)
            return new("audit_export", name, CheckStatus.Warning, "Off: audit_log stays in PostgreSQL only.",
                "Deploy with BB_PROFILE=production (Data Collection Rule + BlueboardAudit_CL), see docs/OPERATIONS.md.");
        if (AuditExporter.EndpointProblem(settings.AuditDceEndpoint) is { } problem)
            return new("audit_export", name, CheckStatus.Failed, problem, "Set AUDIT_DCE_ENDPOINT to the Data Collection Endpoint's logs ingestion URL.");
        try
        {
            var mark = await new KvState(db).GetAsync<AuditExporter.Mark>(KvState.AuditExportMark, ct);
            await using var cmd = db.Command("select count(*) from audit_log where id > @m").With("m", mark?.LastId ?? 0);
            var behind = Convert.ToInt64(await cmd.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
            if (mark?.Error is { } e && (mark.SentAt is null || mark.ErrorAt > mark.SentAt))
                return new("audit_export", name, CheckStatus.Failed, $"Last export failed {Ago(mark.ErrorAt!.Value)}: {e}. {behind} row(s) waiting.",
                    "Check the board identity has Monitoring Metrics Publisher on the Data Collection Rule (infra/main.bicep, production profile).");
            return behind > 1000
                ? new("audit_export", name, CheckStatus.Warning, $"{behind} audit rows waiting to be sent.", "Check Application Insights for the export-audit function.")
                : new("audit_export", name, CheckStatus.Ok, mark?.SentAt is { } at ? $"Last batch sent {Ago(at)}; {behind} row(s) waiting." : $"On; nothing sent yet ({behind} row(s) waiting).");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return new("audit_export", name, CheckStatus.Failed, "Couldn't read the export state from the database.");
        }
    }

    // helpers --------------------------------------------------------------------------------------
    private static string Short(Exception ex) => ex switch
    {
        BoardException b => b.Message.Length > 200 ? b.Message[..200] : b.Message,
        OperationCanceledException => "timed out",
        _ => ex.GetType().Name,
    };

    internal static string Ago(DateTimeOffset t)
    {
        var s = (DateTimeOffset.UtcNow - t).TotalSeconds;
        if (s < 90) return "just now";
        if (s < 5400) return $"{Math.Round(s / 60)} minutes ago";
        if (s < 172800) return $"{Math.Round(s / 3600)} hours ago";
        return $"{Math.Round(s / 86400)} days ago";
    }

    /// <summary>`blueboard doctor` output: one line per check, then detail lines and "How to fix".</summary>
    public static string Format(SetupReport report)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var c in report.Checks)
        {
            sb.Append(c.Status switch { CheckStatus.Ok => "OK      ", CheckStatus.Warning => "WARNING ", _ => "FAILED  " })
              .Append(c.Name).Append(": ").AppendLine(c.Detail);
            foreach (var l in c.Lines ?? []) sb.Append("          ").AppendLine(l);
            if (c.Fix is not null && c.Status != CheckStatus.Ok) sb.Append("          How to fix: ").AppendLine(c.Fix);
        }
        sb.AppendLine(report.Ok ? "blueboard doctor: no failures" : "blueboard doctor: at least one check failed");
        return sb.ToString();
    }
}
