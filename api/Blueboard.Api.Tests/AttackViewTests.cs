using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>WS4: attack timeline building and dedup, attack graph edge derivation, and timeline events in payloads.</summary>
public class AttackViewTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 20, 9, 0, 0, TimeSpan.Zero);
    private const string Dev = "7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e";
    private static int _seq;

    /// <summary>A demo fixture incident with its "@minutesAgo:N" tokens and per-alert windows resolved against T0, as mock-msapi does.</summary>
    private static JsonElement Fixture(string file)
    {
        var o = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "demo-incidents", file)))!.AsObject();
        var created = T0.AddMinutes(-(o["_minutesAgo"]?.GetValue<int>() ?? 10));
        o["createdDateTime"] = created.ToString("O");
        foreach (var a in o["alerts"]!.AsArray())
        {
            var first = a!["_firstMinutesAgo"] is { } f ? T0.AddMinutes(-f.GetValue<int>()) : created;
            var last = a["_lastMinutesAgo"] is { } l ? T0.AddMinutes(-l.GetValue<int>()) : first.AddMinutes(2);
            a["firstActivityDateTime"] = first.ToString("O");
            a["lastActivityDateTime"] = last.ToString("O");
            a["createdDateTime"] = last.AddMinutes(1).ToString("O");
        }
        var text = System.Text.RegularExpressions.Regex.Replace(o.ToJsonString(), "\"@minutesAgo:(\\d+)\"",
            m => $"\"{T0.AddMinutes(-int.Parse(m.Groups[1].Value)):O}\"");
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private static Message Msg(string type, string author, string body, object? payload, DateTimeOffset at, string kind = "agent") => new(
        Guid.NewGuid(), (++_seq).ToString(), "incidents", new Author(author, author, kind), null, Guid.Empty, "1002", type, body,
        payload is null ? null : JsonSerializer.SerializeToElement(payload, BoardJson.Options), [], "open", null, null, at, 0);

    private static TimelineActionInput Action(string kind, object prms, string status, DateTimeOffset at, DateTimeOffset? finished = null, bool dryRun = true) =>
        new(Guid.NewGuid(), kind, status, "enrichment-agent", at, status is "succeeded" or "denied" ? "analyst" : null, status is "succeeded" or "denied" ? at.AddMinutes(1) : null,
            finished, null, JsonSerializer.SerializeToElement(prms), status == "succeeded" ? [("analyst", at.AddMinutes(1))] : [], dryRun, null);

    // ── timeline ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Timeline_is_chronological_and_cites_alerts_evidence_messages_and_actions()
    {
        var data = Fixture("1002-powershell-download.json");
        var finding = Msg("finding", "enrichment-agent", "Malicious script on ws-0142", new
        {
            confidence = 0.85,
            events = new[] { new { ts = T0.AddMinutes(-26).ToString("O"), entity = "ws-0142.contoso.com", action = "scheduled task created", source = "DeviceEvents" } },
        }, T0.AddMinutes(-5));
        var verdict = Msg("verdict", "enrichment-agent", "tp", new { classification = "truePositive", confidence = 0.85 }, T0.AddMinutes(-4));
        var isolate = Action("isolate_device", new { machine_id = Dev }, "succeeded", T0.AddMinutes(-3), T0.AddMinutes(-1));

        var t = IncidentTimeline.Build(Guid.NewGuid(), "1002", data, [finding, verdict], [isolate]);

        Assert.Equal(t.Events.OrderBy(e => e.Ts).Select(e => e.Id), t.Events.Select(e => e.Id));
        Assert.Contains(t.Events, e => e.Kind == "alert" && e.Action.StartsWith("Activity began: Suspicious PowerShell") && e.Refs.Any(r => r.Type == "alert" && r.Id == "da1002-1"));
        // Process starts from processEvidence, in parent → child order.
        var procs = t.Events.Where(e => e.Kind == "evidence" && e.Action.StartsWith("Process started")).ToList();
        Assert.Equal(["WINWORD.EXE", "powershell.exe"], procs.Select(p => p.Action.Split(':')[1].Trim()));
        Assert.All(procs, p => Assert.True(p.InEvidence));
        // The reported event: attributed, marked reported, entity found in evidence, cites the message.
        var reported = Assert.Single(t.Events, e => e.Reported);
        Assert.Equal(["enrichment-agent"], reported.ReportedBy);
        Assert.True(reported.InEvidence);
        Assert.Contains(reported.Refs, r => r.Type == "message" && r.Id == finding.Id.ToString());
        Assert.Contains(t.Events, e => e.Kind == "verdict" && e.Refs.Any(r => r.Id == verdict.Id.ToString()));
        // Requested, approved, executed (dry run), each citing the action id.
        var acts = t.Events.Where(e => e.Kind == "action").ToList();
        Assert.Contains(acts, e => e.Action.StartsWith("@enrichment-agent requested"));
        Assert.Contains(acts, e => e.Action.StartsWith("@analyst approved"));
        Assert.Contains(acts, e => e.Action.StartsWith("Executed (dry run)"));
        Assert.All(acts, e => Assert.Contains(e.Refs, r => r.Type == "action" && r.Id == isolate.Id.ToString()));
        Assert.All(acts, e => Assert.Contains(Dev, e.Entities));
    }

    [Fact]
    public void Same_event_reported_twice_is_one_row_with_both_reporters_and_refs()
    {
        var data = Fixture("1002-powershell-download.json");
        var ev = new { ts = T0.AddMinutes(-29).ToString("O"), entity = "203.0.113.77", action = "First beacon from ws-0142", source = "DeviceNetworkEvents" };
        var evCase = new { ts = T0.AddMinutes(-29).AddMilliseconds(400).ToString("O"), entity = "203.0.113.77 ", action = "first beacon from WS-0142", source = "hunt" };
        var a = Msg("finding", "agent-a", "a", new { events = new[] { ev } }, T0.AddMinutes(-5));
        var b = Msg("ioc", "agent-b", "b", new { indicators = new[] { new { kind = "ip", value = "203.0.113.77", verdict = "suspicious" } }, events = new[] { evCase } }, T0.AddMinutes(-4));

        var t = IncidentTimeline.Build(Guid.NewGuid(), "1002", data, [a, b], []);

        var row = Assert.Single(t.Events, e => e.Reported);
        Assert.Equal(["agent-a", "agent-b"], row.ReportedBy);
        Assert.Equal(2, row.Refs.Count(r => r.Type == "message"));
        Assert.Equal(t.Events.Count, t.Events.Select(e => e.Id).Distinct().Count());
    }

    [Fact]
    public void Reported_event_on_an_entity_not_in_evidence_is_flagged()
    {
        var data = Fixture("1002-powershell-download.json");
        var spoof = Msg("finding", "rogue-agent", "trust me", new
        {
            events = new[] { new { ts = T0.AddMinutes(-40).ToString("O"), entity = "dc01.contoso.com", action = "attacker logged on to the domain controller" } },
        }, T0.AddMinutes(-2));

        var e = Assert.Single(IncidentTimeline.Build(Guid.NewGuid(), "1002", data, [spoof], []).Events, x => x.Reported);
        Assert.False(e.InEvidence);
        Assert.Equal("attack", e.Lane);
        Assert.Contains("rogue-agent", e.ReportedBy);
    }

    [Fact]
    public void Release_after_isolate_on_the_same_device_is_a_revert()
    {
        var data = Fixture("1002-powershell-download.json");
        var isolate = Action("isolate_device", new { machine_id = Dev }, "succeeded", T0.AddMinutes(-30), T0.AddMinutes(-28));
        var release = Action("release_device", new { machine_id = Dev }, "succeeded", T0.AddMinutes(-10), T0.AddMinutes(-8));

        var t = IncidentTimeline.Build(Guid.NewGuid(), "1002", data, [], [release, isolate]);

        var revert = Assert.Single(t.Events, e => e.Action.StartsWith("Reverted"));
        Assert.Contains(revert.Refs, r => r.Id == isolate.Id.ToString());
        Assert.Contains(revert.Refs, r => r.Id == release.Id.ToString());
    }

    [Fact]
    public void Timeline_filters_by_entity_and_source_and_limits()
    {
        var data = Fixture("1003-impossible-travel.json");
        var t = IncidentTimeline.Build(Guid.NewGuid(), "1003", data, [], []);
        Assert.Contains(t.Events, e => e.Action.StartsWith("Sign-in session started (IMAP"));
        var onIp = IncidentTimeline.Build(Guid.NewGuid(), "1003", data, [], [], entityFilter: "203.0.113.200");
        Assert.NotEmpty(onIp.Events);
        Assert.All(onIp.Events, e => Assert.Contains(e.Entities, x => x.Contains("203.0.113.200")));
        var alertsOnly = IncidentTimeline.Build(Guid.NewGuid(), "1003", data, [], [], kindFilter: "alert");
        Assert.All(alertsOnly.Events, e => Assert.Equal("alert", e.Kind));
        var one = IncidentTimeline.Build(Guid.NewGuid(), "1003", data, [], [], limit: 1);
        Assert.Single(one.Events);
        Assert.True(one.Truncated);
        Assert.Equal(t.Events.Count, one.Total);
    }

    // ── payload validation (spoofed or malformed events from agents) ─────────────────────────

    [Theory]
    [InlineData("""{"events":[{"ts":"not a date","entity":"x","action":"y"}]}""", "ts must be")]
    [InlineData("""{"events":[{"ts":"2099-01-01T00:00:00Z","entity":"x","action":"y"}]}""", "in the future")]
    [InlineData("""{"events":[{"ts":"2026-11-20T09:00:00Z","entity":"","action":"y"}]}""", "entity must be")]
    [InlineData("""{"events":[{"ts":"2026-11-20T09:00:00Z","entity":"x"}]}""", "action must be")]
    [InlineData("""{"events":{}}""", "must be an array")]
    [InlineData("""{"events":[]}""", "1–200 events")]
    public void Bad_timeline_events_are_refused(string payload, string expected)
    {
        var ex = Assert.Throws<BoardException>(() => Payloads.Validate("finding", JsonDocument.Parse(payload).RootElement));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void Timeline_events_are_normalised_on_finding_and_ioc()
    {
        var f = Payloads.Validate("finding", JsonDocument.Parse("""
            {"confidence":0.5,"events":[{"ts":"2026-11-20T19:00:00+10:00","entity":" ws-1\n","action":"ran\tx","source":"hunt","extra":"dropped"}]}
            """).RootElement);
        var e = f.GetProperty("events")[0];
        Assert.Equal("2026-11-20T09:00:00.0000000+00:00", e.GetProperty("ts").GetString());
        Assert.Equal("ws-1", e.GetProperty("entity").GetString());
        Assert.Equal("ran x", e.GetProperty("action").GetString());
        Assert.False(e.TryGetProperty("extra", out _));

        var i = Payloads.Validate("ioc", JsonDocument.Parse("""
            {"indicators":[{"kind":"ip","value":"203.0.113.9","verdict":"suspicious"}],"events":[{"ts":"2026-11-20T09:00:00Z","entity":"203.0.113.9","action":"beacon"}]}
            """).RootElement);
        Assert.Equal(1, i.GetProperty("events").GetArrayLength());
    }

    [Fact]
    public void Add_timeline_events_contract_validates_and_has_a_schema()
    {
        var schema = Contract.SchemaFor<AddTimelineEventsInput>();
        Assert.Equal("array", schema["properties"]!["events"]!["type"]!.GetValue<string>());
        var ex = Assert.Throws<ContractException>(() => Contract.Read<AddTimelineEventsInput>(JsonSerializer.SerializeToElement(new { incident = "1", summary = "short" })));
        Assert.Contains("events", ex.Message);
    }

    // ── graph ─────────────────────────────────────────────────────────────────────────────────

    private static IncidentGraphResult Graph(string file, IReadOnlyList<Message>? messages = null, IReadOnlyList<GraphActionInput>? actions = null, Policy? policy = null, bool admin = false) =>
        IncidentGraph.Build(Guid.NewGuid(), "x", Fixture(file), messages ?? [], actions ?? [], policy ?? new Policy(), admin);

    private static GraphNode Node(IncidentGraphResult g, string key) => Assert.Single(g.Nodes, n => n.Keys.Contains(key, StringComparer.OrdinalIgnoreCase));

    private static bool HasEdge(IncidentGraphResult g, string from, string relation, string to, bool? inferred = null) =>
        g.Edges.Any(e => e.From == Node(g, from).Id && e.To == Node(g, to).Id && e.Relation == relation && (inferred is null || e.Inferred == inferred));

    [Fact]
    public void Endpoint_graph_derives_process_tree_user_device_and_network_edges()
    {
        var g = Graph("1002-powershell-download.json");
        // Device merged across alerts by MDE id and name.
        var device = Node(g, Dev);
        Assert.Contains("ws-0142.contoso.com", device.Keys);
        Assert.Equal(["da1002-1", "da1002-2"], device.AlertIds);
        Assert.True(device.Compromised); // roles: compromised
        Assert.True(HasEdge(g, "sam.patel@contoso.com", "logged on to", Dev, inferred: false));
        Assert.True(HasEdge(g, Dev, "connected from", "198.51.100.14", inferred: false));
        var word = Assert.Single(g.Nodes, n => n.Kind == "process" && n.Label == "WINWORD.EXE");
        var ps = Assert.Single(g.Nodes, n => n.Kind == "process" && n.Label == "powershell.exe");
        Assert.Contains(g.Edges, e => e.From == word.Id && e.To == ps.Id && e.Relation == "spawned" && !e.Inferred);
        Assert.Contains(g.Edges, e => e.From == device.Id && e.To == ps.Id && e.Relation == "ran");
        Assert.Equal("malicious", ps.Verdict);
        Assert.True(HasEdge(g, "https://cdn-update-check.example/update-check.ps1", "hosted on", "cdn-update-check.example"));
        Assert.True(HasEdge(g, "cdn-update-check.example", "resolves to", "203.0.113.77", inferred: false));
        // The download URL in the command line is a co-occurrence edge, marked inferred.
        Assert.Contains(g.Edges, e => e.From == ps.Id && e.To == Node(g, "https://cdn-update-check.example/update-check.ps1").Id && e.Inferred);
        Assert.Equal(g.Edges.Count, g.Edges.Select(e => (e.From, e.To, e.Relation)).Distinct().Count());
    }

    [Fact]
    public void Email_graph_links_sender_message_recipient_and_url()
    {
        var g = Graph("1001-phishing-url.json");
        var mail = Assert.Single(g.Nodes, n => n.Kind == "email");
        Assert.Contains(g.Edges, e => e.From == Node(g, "payroll-notice@contoso-payroll-update.example").Id && e.To == mail.Id && e.Relation == "sent");
        // The recipient mailbox is the same node as the user from userEvidence.
        var ana = Node(g, "ana.lopez@contoso.com");
        Assert.Equal("user", ana.Kind);
        Assert.Contains(g.Edges, e => e.From == mail.Id && e.To == ana.Id && e.Relation == "delivered to");
        Assert.Contains(g.Edges, e => e.From == mail.Id && e.To == Node(g, "https://contoso-payroll-update.example/login").Id && e.Relation == "contains link");
        Assert.Contains(g.Edges, e => e.From == mail.Id && e.To == Node(g, "192.0.2.45").Id && e.Relation == "sent from");
    }

    [Fact]
    public void Sign_in_sessions_link_user_to_ips_and_iocs_raise_verdicts()
    {
        var ioc = Msg("ioc", "analyst", "iocs", new { indicators = new[] { new { kind = "ip", value = "203.0.113.200", verdict = "malicious" }, new { kind = "domain", value = "not-in-evidence.example", verdict = "malicious" } } }, T0, kind: "human");
        var g = Graph("1003-impossible-travel.json", [ioc]);
        Assert.True(HasEdge(g, "j.chen@contoso.com", "signed in from", "198.51.100.23", inferred: false));
        Assert.True(HasEdge(g, "j.chen@contoso.com", "signed in from", "203.0.113.200", inferred: false));
        Assert.Equal("malicious", Node(g, "203.0.113.200").Verdict);
        var extra = Node(g, "not-in-evidence.example");
        Assert.False(extra.InEvidence);
        Assert.True(Node(g, "203.0.113.200").InEvidence);
    }

    [Fact]
    public void Protected_nodes_are_flagged_and_named_only_for_admins_and_actions_mark_targets()
    {
        var policy = new Policy { ProtectedUsers = ["sam.patel@contoso.com"], ProtectedIndicators = ["example"] };
        var actions = new List<GraphActionInput>
        {
            new("isolate_device", "pending_approval", JsonSerializer.SerializeToElement(new { machine_id = Dev }), false),
            new("block_indicator", "succeeded", JsonSerializer.SerializeToElement(new { indicator_type = "ip", value = "203.0.113.77", title = "c2 server" }), false),
        };
        var analyst = Graph("1002-powershell-download.json", actions: actions, policy: policy);
        var sam = Node(analyst, "sam.patel@contoso.com");
        Assert.True(sam.Protected);
        Assert.Null(sam.ProtectedAs);
        Assert.True(Node(analyst, "cdn-update-check.example").Protected); // subdomain of a protected indicator
        Assert.False(Node(analyst, "203.0.113.77").Protected);
        Assert.Equal(["isolate_device"], Node(analyst, Dev).PendingActions);
        Assert.Equal(["block_indicator"], Node(analyst, "203.0.113.77").ExecutedActions);

        var admin = Graph("1002-powershell-download.json", actions: actions, policy: policy, admin: true);
        Assert.Equal("sam.patel@contoso.com", Node(admin, "sam.patel@contoso.com").ProtectedAs);
    }

    [Fact]
    public void Template_incidents_build_graphs_without_dangling_edges()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "demo-incidents");
        foreach (var f in Directory.GetFiles(dir, "*.json"))
        {
            var g = Graph(Path.GetFileName(f));
            Assert.NotEmpty(g.Nodes);
            var ids = g.Nodes.Select(n => n.Id).ToHashSet();
            Assert.All(g.Edges, e => { Assert.Contains(e.From, ids); Assert.Contains(e.To, ids); Assert.NotEqual(e.From, e.To); });
            Assert.Equal(ids.Count, g.Nodes.Count);
        }
    }
}
