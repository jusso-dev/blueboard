using Blueboard.Contracts;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Ops;

// blueboard migrate                 apply db/migrations (DATABASE_URL, or PGHOST + PG_ENTRA_AUTH=true; as
//                                   DATABASE_MIGRATE_URL / PG_MIGRATE_USER when set, see db/migrations/009)
// blueboard seed-dev [--sample]     local principals with roles, plus optional sample incidents (refused in Azure)
// blueboard policy-check [file]     validate a policy file (default BLUEBOARD_POLICY_FILE); exit 1 on error
// blueboard doctor [--json]         the setup checklist (same checks as /api/setup); exit 1 if any check failed
// blueboard playbooks [dir]         validate playbooks/*.md and list what each matches (exit 1 if any file is bad)
var cmd = args.FirstOrDefault() ?? "help";
var settings = Settings.FromEnvironment();

if (cmd == "policy-check")
{
    // No database needed: this runs in CI and before a deploy.
    var file = args.Skip(1).FirstOrDefault() ?? settings.PolicyFile;
    if (file is null)
    {
        Console.Error.WriteLine("usage: blueboard policy-check <policy.json> (or set BLUEBOARD_POLICY_FILE)");
        return 1;
    }
    try
    {
        Console.Write(PolicyReport.Build(Policy.LoadFile(file)).ToText());
        Console.WriteLine($"\n{file}: ok");
        return 0;
    }
    catch (PolicyException ex)
    {
        Console.Error.WriteLine($"error: {ex.Message}");
        return 1;
    }
}

if (cmd == "playbooks")
{
    // No database needed: runs in CI and before a deploy.
    var set = Playbooks.Load(args.Length > 1 ? args[1] : Path.Combine(AppContext.BaseDirectory, "playbooks"));
    foreach (var p in set.All) Console.WriteLine($"ok   {p.File}: {p.Id} (priority {p.Priority}), {p.Steps.Count} steps");
    foreach (var p in set.Problems) Console.WriteLine($"FAIL {p.File}: {p.Error}");
    return set.Problems.Count == 0 ? 0 : 1;
}

if (cmd == "help")
{
    Console.WriteLine("usage: blueboard migrate | seed-dev [--sample] | policy-check [file] | doctor [--json] | retention [--days n] [--apply] | playbooks [dir]");
    return 0;
}

await using var db = new Db(settings);

switch (cmd)
{
    case "migrate":
        var applied = await new Migrator(db, settings).RunAsync(Path.Combine(AppContext.BaseDirectory, "migrations"));
        Console.WriteLine(applied.Count == 0 ? "up to date" : $"applied {string.Join(", ", applied)}");
        break;

    case "seed-dev":
        if (Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID") is not null || !settings.DevAuth)
        {
            Console.Error.WriteLine("seed-dev is for local development only (needs DEV_AUTH=true, refused in Azure)");
            return 1;
        }
        await Seed.PrincipalsAsync(db);
        if (args.Contains("--sample"))
        {
            var audit = new Audit(db);
            var board = new BoardService(db, audit, settings);
            var system = new SystemPrincipal(db);
            var runner = new PlaybookRunner(db, board, system, Playbooks.Load(Path.Combine(AppContext.BaseDirectory, "playbooks")));
            var ingest = new Ingest(db, board, new MsClient(new HttpClient()), system, settings, runner);
            Console.WriteLine($"sample incident: {await ingest.UpsertAsync(Seed.SampleIncident())}");
            Console.WriteLine($"sample phishing incident: {await ingest.UpsertAsync(Seed.PhishingIncident())}");
        }
        Console.WriteLine("seeded");
        break;

    case "retention":
    {
        // Preview by default; --apply removes. --days overrides RETENTION_DAYS. Runs as the board's runtime database role.
        int? days = null;
        var i = Array.IndexOf(args, "--days");
        if (i >= 0 && (i + 1 >= args.Length || !int.TryParse(args[i + 1], out var parsed) || parsed < Retention.MinimumDays))
        {
            Console.Error.WriteLine($"--days needs a number of at least {Retention.MinimumDays}");
            return 1;
        }
        else if (i >= 0) days = int.Parse(args[i + 1]);
        if (days is null && settings.RetentionDays <= 0)
        {
            Console.Error.WriteLine("RETENTION_DAYS is off: pass --days <n> to preview a retention period");
            return 1;
        }
        var apply = args.Contains("--apply");
        var r = await new Retention(db, new Audit(db), new SystemPrincipal(db), settings).RunAsync(dryRun: !apply, days, CancellationToken.None);
        Console.WriteLine($"{(apply ? "removed" : "would remove")} (older than {r.Days} days, before {r.Cutoff:yyyy-MM-dd}): " +
                          $"{r.Incidents} incident(s), {r.Messages} message(s), {r.Actions} action(s), {r.Deliveries} delivery record(s)");
        if (!apply) Console.WriteLine("dry run: nothing was removed (pass --apply to remove; the first preview counts one batch of up to " + Retention.BatchSize + " incidents and threads)");
        break;
    }

    case "doctor":
    {
        // Run with the board's own settings and identity (on the Function App, or locally with az login as a stand-in).
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        var ms = new MsClient(http);
        var notifier = new Notifier(new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false }), db, new Audit(db), ms, settings);
        var policy = Policy.Load(settings);
        // Connector health is read from the database only (connector_status): no connector is called from the CLI.
        var audit = new Audit(db);
        var board = new BoardService(db, audit, settings);
        var sys = new SystemPrincipal(db);
        var connectors = Blueboard.Api.Connectors.ConnectorHub.Create(db, audit, board, sys, settings, policy,
            new PlaybookRunner(db, board, sys, PlaybookSet.Empty), new RateLimiter(db, audit, policy), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        var report = await new Setup(db, settings, policy, ms, notifier, connectors).RunAsync();
        Console.Write(args.Contains("--json") ? Json.Serialize(report) + "\n" : Setup.Format(report));
        return report.Ok ? 0 : 1;
    }

    default:
        Console.WriteLine("usage: blueboard migrate | seed-dev [--sample] | policy-check [file] | doctor [--json] | retention [--days n] [--apply] | playbooks [dir]");
        return 1;
}
return 0;

internal static class Seed
{
    private static readonly (string Handle, string Name, string Kind, string[] Roles, string? Description)[] Principals =
    [
        ("analyst", "SOC Analyst (dev)", "human", ["poster", "hunter", "requester", "approver", "admin"], null),
        ("analyst2", "Second Analyst (dev)", "human", ["poster", "hunter", "requester", "approver"], null),
        ("enrichment-agent", "Enrichment Agent", "agent", ["poster", "hunter", "requester"], "Reference Claude agent: enriches incidents, answers questions, proposes containment"),
        ("observer-bot", "Observer Bot", "agent", ["poster"], "Posts only"),
        ("my-agent", "My Agent (template)", "agent", ["poster"], "Your own agent: see docs/AGENTS.md and agents/Blueboard.AgentTemplate"),
    ];

    public static async Task PrincipalsAsync(Db db)
    {
        foreach (var p in Principals)
        {
            await using var c = db.Command("""
                insert into principals (handle, display_name, kind, roles, description) values (@h, @n, @k, @r, @d)
                on conflict (handle) do update set roles = excluded.roles, display_name = excluded.display_name, description = excluded.description
                """).With("h", p.Handle).With("n", p.Name).With("k", p.Kind).With("r", p.Roles).With("d", p.Description);
            await c.ExecuteNonQueryAsync();
        }
    }

    public static JsonElement SampleIncident()
    {
        var now = DateTimeOffset.UtcNow;
        const string device = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";
        return JsonSerializer.SerializeToElement(new Dictionary<string, object>
        {
            ["id"] = "90210",
            ["displayName"] = "Multi-stage incident involving Initial access & Credential access on one endpoint",
            ["severity"] = "high",
            ["status"] = "active",
            ["incidentWebUrl"] = "https://security.microsoft.com/incidents/90210",
            ["createdDateTime"] = now.AddHours(-1).ToString("O"),
            ["lastUpdateDateTime"] = now.ToString("O"),
            ["alerts"] = new object[]
            {
                new Dictionary<string, object>
                {
                    ["id"] = "da637f-sample-1", ["title"] = "Suspicious PowerShell download cradle", ["severity"] = "high",
                    ["serviceSource"] = "microsoftDefenderForEndpoint", ["mitreTechniques"] = new[] { "T1059.001", "T1105" },
                    ["evidence"] = new object[]
                    {
                        new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.deviceEvidence", ["mdeDeviceId"] = device, ["deviceDnsName"] = "fin-lt-0423.contoso.local" },
                        new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.userEvidence", ["userAccount"] = new { userPrincipalName = "j.doe@contoso.com", azureAdUserId = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f", displayName = "Jane Doe" } },
                        new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.ipEvidence", ["ipAddress"] = "203.0.113.45" },
                        new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.urlEvidence", ["url"] = "https://cdn-update-check.example.net/payload.ps1" },
                        new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.fileEvidence", ["fileDetails"] = new { fileName = "update.exe", sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", sha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" } },
                    },
                },
                new Dictionary<string, object>
                {
                    ["id"] = "da637f-sample-2", ["title"] = "Possible credential theft via LSASS access", ["severity"] = "high",
                    ["serviceSource"] = "microsoftDefenderForEndpoint", ["mitreTechniques"] = new[] { "T1003.001" },
                    ["evidence"] = new object[] { new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.deviceEvidence", ["mdeDeviceId"] = device, ["deviceDnsName"] = "fin-lt-0423.contoso.local" } },
                },
            },
        });
    }

    public static JsonElement PhishingIncident()
    {
        var now = DateTimeOffset.UtcNow;
        return JsonSerializer.SerializeToElement(new Dictionary<string, object>
        {
            ["id"] = "90211",
            ["displayName"] = "Email messages containing malicious URL removed after delivery",
            ["severity"] = "medium",
            ["status"] = "active",
            ["incidentWebUrl"] = "https://security.microsoft.com/incidents/90211",
            ["createdDateTime"] = now.AddMinutes(-40).ToString("O"),
            ["lastUpdateDateTime"] = now.AddMinutes(-5).ToString("O"),
            ["alerts"] = new object[]
            {
                new Dictionary<string, object>
                {
                    ["id"] = "fa637f-sample-3", ["title"] = "Email messages containing malicious URL removed after delivery", ["severity"] = "medium",
                    ["category"] = "InitialAccess", ["serviceSource"] = "microsoftDefenderForOffice365", ["mitreTechniques"] = new[] { "T1566.002" },
                    ["evidence"] = new object[]
                    {
                        new Dictionary<string, object>
                        {
                            ["@odata.type"] = "#microsoft.graph.security.analyzedMessageEvidence", ["networkMessageId"] = "0b9a5e1c-7d2f-4e3a-9c8b-1f2e3d4c5b6a",
                            ["recipientEmailAddress"] = "a.lee@contoso.com", ["subject"] = "Action required: payroll update",
                            ["p1Sender"] = new { emailAddress = "payroll@contoso-hr.example" }, ["urls"] = new[] { "https://contoso-hr.example/login" },
                        },
                        new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.mailboxEvidence", ["primaryAddress"] = "a.lee@contoso.com" },
                        new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.urlEvidence", ["url"] = "https://contoso-hr.example/login" },
                    },
                },
            },
        });
    }
}
