using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Blueboard.Api.Intel;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>WS2: detection back-tests and rules, Intune patching kinds, exposure prioritisation.</summary>
public class DetectionsExposureTests
{
    private const string Mde = "7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e";
    private const string Managed = "3f6a0b1c-0142-4a6b-9e2d-0c1d2e3f4a5b";
    private const string Aad = "5d0c8a51-0142-4c3e-9a10-7c3f9e2a1b8d";
    private const string Query = "DeviceProcessEvents | where ProcessCommandLine has 'EncodedCommand'";
    private static readonly DateTimeOffset Now = new(2026, 11, 27, 9, 0, 0, TimeSpan.Zero);

    private static JsonElement El(object o) => JsonSerializer.SerializeToElement(o);

    private static object Rule(string? query = null, string? target = null, object? extra = null)
    {
        var o = new Dictionary<string, object?>
        {
            ["target"] = target ?? "defender", ["name"] = "Encoded PowerShell", ["query"] = query ?? Query,
            ["backtest_id"] = "0b6c2f1e-1001-4a7b-9c3d-000000000001",
        };
        if (extra is not null) foreach (var p in El(extra).EnumerateObject()) o[p.Name] = p.Value;
        return o;
    }

    private static JsonObject Valid(object rule) => Catalog.Get("create_detection_rule").Validate(El(rule));

    private static ActionContext Ctx(JsonObject? facts = null, TiSettings? ti = null) =>
        new(Guid.Parse("11111111-2222-3333-4444-555555555555"), "90210", null, "agent", "analyst", "because evidence", ti ?? new TiSettings(), Now, facts);

    // ── create_detection_rule parameter validation ─────────────────────────────────────────────

    [Fact]
    public void Create_rule_validates_and_defaults()
    {
        var p = Valid(Rule());
        Assert.Equal("PT1H", p["frequency"]!.GetValue<string>());
        Assert.Equal("PT1H", p["lookback"]!.GetValue<string>());
        Assert.Equal("medium", p["severity"]!.GetValue<string>());
        Assert.True(p["enabled"]!.GetValue<bool>());
        Assert.Empty(p["mitre"]!.AsArray());
    }

    [Theory]
    [InlineData("DeviceEvents | take 1; .drop table DeviceEvents", "management commands")]
    [InlineData("externaldata(x:string) [@'https://evil.example/a.csv']", "external data")]
    [InlineData("DeviceEvents | evaluate http_request('https://evil.example')", "external data")]
    [InlineData("DeviceEvents /* unclosed", "unclosed comment")]
    public void Rule_kql_goes_through_the_hunting_guards(string query, string expected)
    {
        var ex = Assert.Throws<BoardException>(() => Valid(Rule(query)));
        Assert.Contains(expected, ex.Message);
    }

    [Theory]
    [InlineData("DeviceProcessEvents | where Timestamp > ago(1h)", "ago")]
    [InlineData("DeviceProcessEvents | where Timestamp > now() - 1h", "now")]
    [InlineData("DeviceProcessEvents | take 10", "take")]
    [InlineData("DeviceProcessEvents | limit 10", "limit")]
    [InlineData("DeviceProcessEvents | sample 10", "sample")]
    [InlineData("DeviceProcessEvents\n| TAKE 5", "take")]
    public void Rule_and_backtest_kql_refuse_time_relative_and_row_capping_operators(string query, string op)
    {
        var ex = Assert.Throws<BoardException>(() => Valid(Rule(query)));
        Assert.Contains($"may not use {op}", ex.Message);
        Assert.Throws<BoardException>(() => Enrichment.ValidateDetectionKql(query));
    }

    [Theory]
    [InlineData("DeviceProcessEvents | where ProcessCommandLine has 'take 10'")]
    [InlineData("DeviceProcessEvents | where ProcessCommandLine has \"ago(1h)\" // limit 5")]
    [InlineData("DeviceProcessEvents | where InitiatingProcessFileName == 'sample.exe' /* now() */")]
    [InlineData("DeviceProcessEvents | extend Taken = 1, limit_reached = false | where Taken == 1")]
    public void Detection_guard_ignores_operators_inside_strings_comments_and_names(string query) =>
        Enrichment.ValidateDetectionKql(query);

    [Theory]
    [InlineData("workspace('other').SecurityEvent | count", "workspace")]
    [InlineData("app('x').requests", "app")]
    [InlineData("adx('https://help.kusto.windows.net/Samples').StormEvents", "adx")]
    [InlineData("cluster('c').database('d').T", "cluster")]
    [InlineData("database('d').T", "database")]
    [InlineData("arg('').Resources | take 1", "arg")]
    [InlineData("DeviceEvents | union (Workspace ( 'x' ).Heartbeat)", "workspace")]
    public void Hunting_backtest_and_rule_kql_refuse_cross_resource_functions(string query, string fn)
    {
        Assert.Contains($"({fn}())", Assert.Throws<BoardException>(() => Enrichment.ValidateKql(query, "P1D")).Message);
        Assert.Throws<BoardException>(() => Valid(Rule(query)));
    }

    [Theory]
    [InlineData("DeviceProcessEvents | where ProcessCommandLine has \"workspace('x')\"")]
    [InlineData("DeviceProcessEvents | where AppName == 'app' // app('x') in a comment")]
    [InlineData("DeviceProcessEvents | extend myapp(x) = 1")]
    [InlineData("DeviceProcessEvents | where FolderPath has 'database'")]
    public void Cross_resource_guard_ignores_strings_comments_and_other_names(string query) =>
        Enrichment.ValidateKql(query, "P1D");

    [Fact]
    public void Peak_day_volume_and_overlapping_lookback_are_enforced_not_just_the_average()
    {
        // 14 days, average 50/day, but one day had 600 hits: the average passes, the peak does not.
        var burst = new BacktestRecord(Guid.NewGuid(), "defender", DetectionService.QueryHash(Query), 14, 700, 50, 600, Now.AddHours(-2));
        Assert.Contains("peaked at 600 hits", Resolvers.BacktestFacts(burst, "defender", DetectionService.QueryHash(Query), Now, "PT1H", "PT1H").Reject);
        // A Sentinel rule running hourly over a 1-day lookback matches each row 24 times.
        var steady = new BacktestRecord(Guid.NewGuid(), "sentinel", DetectionService.QueryHash(Query), 14, 280, 20, 30, Now.AddHours(-2));
        Assert.Null(Resolvers.BacktestFacts(steady, "sentinel", DetectionService.QueryHash(Query), Now, "PT1H", "PT1H").Reject);
        Assert.Contains("frequency and lookback", Resolvers.BacktestFacts(steady, "sentinel", DetectionService.QueryHash(Query), Now, "PT1H", "P1D").Reject);
        Assert.Equal(30 * 24, Resolvers.PeakAlertsPerDay(steady, "sentinel", "PT1H", "P1D"));
        // Defender derives its lookback from the frequency: no overlap factor.
        Assert.Equal(30, Resolvers.PeakAlertsPerDay(steady, "defender", "PT1H", "P1D"));
    }

    [Theory]
    [InlineData(new object[] { "{\"backtest_id\":null}", "backtest_id is required" })]
    [InlineData(new object[] { "{\"backtest_id\":\"not-a-guid\"}", "invalid backtest_id" })]
    [InlineData(new object[] { "{\"frequency\":\"PT5M\"}", "frequency must be one of" })]
    [InlineData(new object[] { "{\"frequency\":\"P1D\",\"lookback\":\"PT1H\"}", "lookback must be at least frequency" })]
    [InlineData(new object[] { "{\"severity\":\"critical\"}", "severity must be one of" })]
    [InlineData(new object[] { "{\"mitre\":[{\"tactic\":\"Hacking\"}]}", "tactic must be one of" })]
    [InlineData(new object[] { "{\"mitre\":[{\"tactic\":\"Execution\",\"techniques\":[\"1059\"]}]}", "invalid MITRE technique" })]
    [InlineData(new object[] { "{\"entity_mappings\":[{\"entity\":\"host.name\",\"column\":\"Device Name\"}]}", "invalid column" })]
    [InlineData(new object[] { "{\"entity_mappings\":[{\"entity\":\"host.name\",\"column\":\"A\"},{\"entity\":\"host.name\",\"column\":\"B\"}]}", "mapped once" })]
    [InlineData(new object[] { "{\"enabled\":\"yes\"}", "enabled must be true or false" })]
    [InlineData(new object[] { "{\"name\":\"x\"}", "invalid name" })]
    public void Create_rule_rejects_bad_params(string overrides, string expected)
    {
        var o = (Dictionary<string, object?>)Rule();
        foreach (var p in JsonDocument.Parse(overrides).RootElement.EnumerateObject()) o[p.Name] = p.Value.ValueKind == JsonValueKind.Null ? null : p.Value;
        var ex = Assert.Throws<BoardException>(() => Valid(o));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void Sentinel_rules_refuse_entity_fields_sentinel_cannot_map()
    {
        var ex = Assert.Throws<BoardException>(() => Valid(Rule(target: "sentinel", extra: new { entity_mappings = new[] { new { entity = "host.device_id", column = "DeviceId" } } })));
        Assert.Contains("isn't supported for Sentinel", ex.Message);
    }

    [Fact]
    public void Create_rule_is_never_auto_approved_even_if_listed()
    {
        var def = Catalog.Get("create_detection_rule");
        var policy = new Policy { AutoApprove = ["create_detection_rule"] };
        var d = PolicyEngine.Evaluate(def, Valid(Rule()), null, policy, actionFacts: new ActionFacts(Notes: ["back-test ok"]));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Equal("approval", PolicyReport.ModeOf("create_detection_rule", policy));
        Assert.Contains(PolicyReport.WarningsFor(policy), w => w.Contains("create_detection_rule") && w.Contains("always needs a human"));
        Assert.DoesNotContain("create_detection_rule", new Policy().AutoApprove);
    }

    // ── back-test hash binding ─────────────────────────────────────────────────────────────────

    private static BacktestRecord Bt(string? query = null, string target = "defender", int days = 14, double perDay = 3, DateTimeOffset? at = null) =>
        new(Guid.NewGuid(), target, DetectionService.QueryHash(query ?? Query), days, 42, perDay, 9, at ?? Now.AddHours(-2));

    [Fact]
    public void Query_hash_ignores_line_endings_and_outer_whitespace_only()
    {
        Assert.Equal(DetectionService.QueryHash(Query), DetectionService.QueryHash($"  {Query}\r\n"));
        Assert.Equal(DetectionService.QueryHash("a\r\nb"), DetectionService.QueryHash("a\nb"));
        Assert.NotEqual(DetectionService.QueryHash(Query), DetectionService.QueryHash(Query.Replace("has", "has_cs")));
        Assert.Matches("^[0-9a-f]{64}$", DetectionService.QueryHash(Query));
    }

    [Fact]
    public void Matching_recent_backtest_binds_and_its_volumes_reach_the_approver()
    {
        var f = Resolvers.BacktestFacts(Bt(), "defender", DetectionService.QueryHash(Query), Now);
        Assert.Null(f.Reject);
        Assert.Contains(f.Notes!, n => n.Contains("42 hits") && n.Contains("alerts a day"));
    }

    [Fact]
    public void Backtest_of_a_different_query_is_refused()
    {
        var f = Resolvers.BacktestFacts(Bt("DeviceProcessEvents | where FileName == 'calc.exe'"), "defender", DetectionService.QueryHash(Query), Now);
        Assert.Contains("is not the query back-tested", f.Reject);
    }

    [Theory]
    [InlineData("sentinel", 14, 3.0, -2, "ran against defender")]
    [InlineData("defender", 3, 3.0, -2, "at least 7 are needed")]
    [InlineData("defender", 14, 3.0, -25, "24 hours")]
    [InlineData("defender", 14, 900.0, -2, "alert flood")]
    public void Backtest_binding_refuses(string ruleTarget, int days, double perDay, int hoursAgo, string expected)
    {
        var f = Resolvers.BacktestFacts(Bt(days: days, perDay: perDay, at: Now.AddHours(hoursAgo)), ruleTarget, DetectionService.QueryHash(Query), Now);
        Assert.Contains(expected, f.Reject);
    }

    [Fact]
    public void Missing_backtest_is_refused_and_policy_rejects_on_facts()
    {
        var f = Resolvers.BacktestFacts(null, "defender", DetectionService.QueryHash(Query), Now);
        Assert.Contains("was not found", f.Reject);
        var d = PolicyEngine.Evaluate(Catalog.Get("create_detection_rule"), Valid(Rule()), null, new Policy(), actionFacts: f);
        Assert.Equal(Outcome.Reject, d.Outcome);
        Assert.Contains("was not found", d.Notes[0]);
    }

    [Fact]
    public void Binding_uses_request_time_so_an_old_approval_still_checks_the_request_window()
    {
        var bt = Bt(at: Now.AddHours(-23));
        Assert.Null(Resolvers.BacktestFacts(bt, "defender", bt.QuerySha256, Now).Reject);
        // A back-test run after the request (forged ordering) is refused.
        Assert.NotNull(Resolvers.BacktestFacts(bt with { CreatedAt = Now.AddHours(1) }, "defender", bt.QuerySha256, Now).Reject);
    }

    // ── back-test arithmetic ───────────────────────────────────────────────────────────────────

    [Fact]
    public void Backtest_math_counts_days_entities_and_estimates()
    {
        Dictionary<string, JsonElement> Row(string ts, string dev) => new() { ["Timestamp"] = El(ts), ["DeviceName"] = El(dev) };
        var rows = new List<IReadOnlyDictionary<string, JsonElement>>
        {
            Row("2026-11-26T10:00:00Z", "a"), Row("2026-11-26T11:00:00Z", "a"), Row("2026-11-25T10:00:00Z", "b"),
            new Dictionary<string, JsonElement> { ["DeviceName"] = El("c") },
        };
        var s = DetectionMath.Compute(rows, 7, ["DeviceName"], Now);
        Assert.Equal(4, s.TotalHits);
        Assert.Equal(1, s.UndatedHits);
        Assert.Equal(8, s.HitsPerDay.Length); // 7 full days plus today
        Assert.Equal(2, s.HitsPerDay.Single(d => d.Date == "2026-11-26").Hits);
        Assert.Equal(2, s.PeakHitsPerDay);
        Assert.Equal(Math.Round(4.0 / 7, 2), s.EstAlertsPerDay);
        Assert.Equal(3, s.Entities[0].Distinct);
        Assert.Equal(new BacktestValue("a", 2), s.Entities[0].Top[0]);
        Assert.Equal(4, s.Samples.Length);
        Assert.Contains(DetectionMath.Notes(s, 7, truncated: false), n => n.Contains("no Timestamp"));
    }

    [Fact]
    public void Entity_columns_are_validated()
    {
        Assert.Throws<BoardException>(() => DetectionService.ValidColumns(["a", "b", "c", "d", "e", "f"]));
        Assert.Throws<BoardException>(() => DetectionService.ValidColumns(["Device|Name"]));
        Assert.Equal(["DeviceName"], DetectionService.ValidColumns(["DeviceName", "devicename", " "]));
    }

    // ── prepared requests (dry-run preview) ────────────────────────────────────────────────────

    [Fact]
    public void Defender_rule_request_is_tagged_and_maps_entities_and_mitre()
    {
        var p = Valid(Rule(extra: new
        {
            severity = "high",
            mitre = new[] { new { tactic = "Execution", techniques = new[] { "T1059.001" } } },
            entity_mappings = new[] { new { entity = "host.device_id", column = "DeviceId" }, new { entity = "host.name", column = "DeviceName" }, new { entity = "account.upn", column = "AccountUpn" } },
        }));
        var req = Catalog.PrepareCreateRule(p, Ctx())["requests"]![0]!;
        Assert.Equal("POST", req["method"]!.GetValue<string>());
        Assert.Equal("/v1.0/security/rules/detectionRules", req["path"]!.GetValue<string>());
        var body = req["body"]!;
        Assert.Equal("blueboard-11111111222233334444555555555555", body["id"]!.GetValue<string>());
        Assert.StartsWith("[blueboard] ", body["displayName"]!.GetValue<string>());
        Assert.Contains("blueboard action 11111111-2222-3333-4444-555555555555", body["description"]!.GetValue<string>());
        Assert.Equal(Query, body["queryCondition"]!["queryText"]!.GetValue<string>());
        Assert.Equal("enabled", body["status"]!.GetValue<string>());
        var t = body["detectionAction"]!["alertTemplate"]!;
        Assert.Equal("high", t["severity"]!.GetValue<string>());
        Assert.Equal("DeviceId", t["entityMappings"]!["hosts"]![0]!["deviceIdColumn"]!.GetValue<string>());
        Assert.Equal("DeviceName", t["entityMappings"]!["hosts"]![0]!["nameColumn"]!.GetValue<string>());
        Assert.Equal("AccountUpn", t["entityMappings"]!["accounts"]![0]!["upnColumn"]!.GetValue<string>());
        Assert.Equal("T1059.001", t["tactics"]![0]!["techniques"]![0]!["technique"]!.GetValue<string>());
    }

    [Fact]
    public void Sentinel_rule_request_targets_the_configured_workspace()
    {
        var ws = "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/law-soc";
        var p = Valid(Rule(target: "sentinel", extra: new { lookback = "P1D", mitre = new[] { new { tactic = "Execution", techniques = new[] { "T1059.001" } } } }));
        var req = Catalog.PrepareCreateRule(p, Ctx(ti: new TiSettings { SentinelWorkspaceResourceId = ws }))["requests"]![0]!;
        Assert.Equal("PUT", req["method"]!.GetValue<string>());
        Assert.Equal($"{ws}/providers/Microsoft.SecurityInsights/alertRules/11111111-2222-3333-4444-555555555555?api-version=2025-09-01", req["path"]!.GetValue<string>());
        var props = req["body"]!["properties"]!;
        Assert.Equal("Scheduled", req["body"]!["kind"]!.GetValue<string>());
        Assert.Equal("P1D", props["queryPeriod"]!.GetValue<string>());
        Assert.Equal("T1059", props["techniques"]![0]!.GetValue<string>());
        Assert.StartsWith("[blueboard] ", props["displayName"]!.GetValue<string>());
        // Without a valid workspace resource id the request can't be built.
        Assert.Throws<BoardException>(() => Catalog.PrepareCreateRule(p, Ctx(ti: new TiSettings { SentinelWorkspaceResourceId = "/subscriptions/x/../../evil" })));
    }

    [Fact]
    public void Disable_rule_only_uses_the_rule_the_board_created()
    {
        var p = Catalog.Get("disable_detection_rule").Validate(El(new { rule_action_id = "11111111-2222-3333-4444-555555555555" }));
        Assert.Throws<BoardException>(() => Catalog.PrepareDisableRule(p, Ctx()));
        var req = Catalog.PrepareDisableRule(p, Ctx(new JsonObject { ["target"] = "defender", ["rule_id"] = "blueboard-abc" }))["requests"]![0]!;
        Assert.Equal("PATCH", req["method"]!.GetValue<string>());
        Assert.Equal("/v1.0/security/rules/detectionRules/blueboard-abc", req["path"]!.GetValue<string>());
        Assert.Equal("disabled", req["body"]!["status"]!.GetValue<string>());
    }

    [Fact]
    public void Expedite_request_is_beta_deployment_plus_audience()
    {
        var p = Catalog.Get("intune_expedite_quality_update").Validate(El(new { managed_device_id = Managed }));
        Assert.Throws<BoardException>(() => Catalog.PrepareExpedite(p, Ctx()));
        var reqs = Catalog.PrepareExpedite(p, Ctx(new JsonObject { ["aad_device_id"] = Aad, ["quality_update_id"] = "abcdef0123456789" }))["requests"]!.AsArray();
        Assert.Equal("/beta/admin/windows/updates/deployments", reqs[0]!["path"]!.GetValue<string>());
        Assert.True(reqs[0]!["body"]!["settings"]!["expedite"]!["isExpedited"]!.GetValue<bool>());
        Assert.Equal("abcdef0123456789", reqs[0]!["body"]!["content"]!["catalogEntry"]!["id"]!.GetValue<string>());
        Assert.Equal(Aad, reqs[1]!["body"]!["addMembers"]![0]!["id"]!.GetValue<string>());
    }

    [Fact]
    public async Task Prepared_steps_run_in_order_and_chain_the_deployment_id()
    {
        var handler = new Scripted(("POST", "/beta/admin/windows/updates/deployments", """{"id":"dep-1"}"""), ("POST", "/beta/admin/windows/updates/deployments/dep-1/audience/updateAudience", ""));
        var ms = new MsClient(new HttpClient(handler), new FakeCredential());
        var p = Catalog.Get("intune_expedite_quality_update").Validate(El(new { machine_id = Mde }));
        var prepared = Catalog.PrepareExpedite(p, Ctx(new JsonObject { ["aad_device_id"] = Aad, ["quality_update_id"] = "abcdef0123456789" }));
        await Catalog.RunPrepared(ms, prepared, "", TestContext.Current.CancellationToken);
        Assert.Equal(["POST /beta/admin/windows/updates/deployments", "POST /beta/admin/windows/updates/deployments/dep-1/audience/updateAudience"], handler.Seen);
    }

    // ── Intune params and alias matching ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("intune_sync_device")]
    [InlineData("intune_update_defender_signatures")]
    [InlineData("intune_expedite_quality_update")]
    public void Intune_kinds_take_exactly_one_device_id(string kind)
    {
        var def = Catalog.Get(kind);
        Assert.Equal(Mde, Catalog.DeviceTarget(def.Validate(El(new { machine_id = Mde.ToUpperInvariant() }))));
        Assert.Equal(Managed, Catalog.DeviceTarget(def.Validate(El(new { managed_device_id = Managed }))));
        Assert.Throws<BoardException>(() => def.Validate(El(new { })));
        Assert.Throws<BoardException>(() => def.Validate(El(new { machine_id = Mde, managed_device_id = Managed })));
        Assert.Throws<BoardException>(() => def.Validate(El(new { managed_device_id = "../../users" })));
        Assert.Equal("device", Catalog.TargetType(kind));
    }

    private static readonly IncidentContext Incident = new("90210", JsonDocument.Parse($$"""
        { "alerts": [ { "evidence": [ { "@odata.type": "#microsoft.graph.security.deviceEvidence", "mdeDeviceId": "{{Mde}}", "deviceDnsName": "ws-0142.contoso.com" } ] } ] }
        """).RootElement);

    private static ActionFacts Resolved(string target) => new(DeviceAliases: new Dictionary<string, string[]>
    {
        [target.ToLowerInvariant()] = [Managed, Aad, Mde, "ws-0142", "ws-0142.contoso.com"],
    });

    [Fact]
    public void Protected_device_listed_by_fqdn_blocks_intune_action_by_managed_id()
    {
        var def = Catalog.Get("intune_sync_device");
        var p = def.Validate(El(new { managed_device_id = Managed }));
        var d = PolicyEngine.Evaluate(def, p, null, new Policy { ProtectedDevices = ["WS-0142.contoso.com"] }, actionFacts: Resolved(Managed));
        Assert.Equal(Outcome.Reject, d.Outcome);
        Assert.Contains("protected device", d.Notes[0]);
    }

    [Fact]
    public void Protected_device_listed_by_mde_id_blocks_intune_action_by_managed_id()
    {
        var def = Catalog.Get("intune_expedite_quality_update");
        var p = def.Validate(El(new { managed_device_id = Managed }));
        Assert.Equal(Outcome.Reject, PolicyEngine.Evaluate(def, p, null, new Policy { ProtectedDevices = [Mde] }, actionFacts: Resolved(Managed)).Outcome);
    }

    [Fact]
    public void Protected_fqdn_matches_intune_short_name_by_host_label()
    {
        var def = Catalog.Get("intune_sync_device");
        var p = def.Validate(El(new { managed_device_id = Managed }));
        var facts = new ActionFacts(DeviceAliases: new Dictionary<string, string[]> { [Managed] = [Managed, "dc01"] });
        var d = PolicyEngine.Evaluate(def, p, null, new Policy { ProtectedDevices = ["dc01.contoso.local"] }, actionFacts: facts);
        Assert.Equal(Outcome.Reject, d.Outcome);
    }

    [Fact]
    public void Managed_id_counts_as_in_evidence_when_its_mde_id_is_and_can_auto_run()
    {
        var def = Catalog.Get("intune_sync_device");
        var p = def.Validate(El(new { managed_device_id = Managed }));
        var policy = new Policy { AutoApprove = ["intune_sync_device"], ProtectedDevices = ["dc01.contoso.local"] };
        Assert.Equal(Outcome.Auto, PolicyEngine.Evaluate(def, p, Incident, policy, actionFacts: Resolved(Managed)).Outcome);
        // Unresolved: the id can't be tied to the evidence or its names, so a person decides.
        var unresolved = PolicyEngine.Evaluate(def, p, Incident, policy, actionFacts: new ActionFacts(UnresolvedDevices: [Managed]));
        Assert.Equal(Outcome.NeedsApproval, unresolved.Outcome);
        Assert.Contains(unresolved.Notes, n => n.Contains("checked by id only"));
    }

    [Fact]
    public void Confirm_names_include_resolved_aliases()
    {
        var def = Catalog.Get("intune_expedite_quality_update");
        var p = def.Validate(El(new { managed_device_id = Managed }));
        var names = PolicyEngine.ConfirmNames(def, p, null, Resolved(Managed));
        Assert.Contains("ws-0142.contoso.com", names, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(Managed, names, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Resolver_links_mde_id_to_intune_and_entra_ids()
    {
        var handler = new Scripted(
            ("GET", $"/api/machines/{Mde}", $$"""{"id":"{{Mde}}","computerDnsName":"ws-0142.contoso.com","aadDeviceId":"{{Aad}}"}"""),
            ("GET", "/v1.0/deviceManagement/managedDevices", $$"""{"value":[{"id":"{{Managed}}","deviceName":"ws-0142","azureADDeviceId":"{{Aad}}"}]}"""));
        var ms = new MsClient(new HttpClient(handler), new FakeCredential());
        var def = Catalog.Get("intune_sync_device");
        var facts = await def.Resolve!(new ResolveContext(null!, ms, new Settings(), Now), def.Validate(El(new { machine_id = Mde })), TestContext.Current.CancellationToken);
        Assert.Equal(Managed, facts.Data!["managed_device_id"]!.GetValue<string>());
        Assert.Contains(Managed, facts.DeviceAliases![Mde]);
        Assert.Contains("ws-0142", facts.DeviceAliases[Mde]);
        Assert.Contains(handler.Seen, s => s.Contains("azureADDeviceId"));
        var prepared = def.Prepare!(def.Validate(El(new { machine_id = Mde })), Ctx(facts.Data));
        Assert.Equal($"/v1.0/deviceManagement/managedDevices/{Managed}/syncDevice", prepared["requests"]![0]!["path"]!.GetValue<string>());
    }

    [Fact]
    public async Task Resolver_reports_a_device_intune_does_not_know()
    {
        var ms = new MsClient(new HttpClient(new Scripted()), new FakeCredential());
        var def = Catalog.Get("intune_sync_device");
        var facts = await def.Resolve!(new ResolveContext(null!, ms, new Settings(), Now), def.Validate(El(new { machine_id = Mde })), TestContext.Current.CancellationToken);
        Assert.Equal([Mde], facts.UnresolvedDevices);
        Assert.Null(facts.Data);
    }

    [Fact]
    public async Task Resolver_fails_closed_when_the_defender_side_finds_nothing_or_fails()
    {
        // The Intune side resolves the managed id, but Defender has no machine for it: the device's MDE names are
        // unknown, so it is reported unresolved (checked by id only, never automatic) even though Intune can act on it.
        var handler = new Scripted(("GET", $"/v1.0/deviceManagement/managedDevices/{Managed}", $$"""{"id":"{{Managed}}","deviceName":"dc01","azureADDeviceId":"{{Aad}}"}"""));
        var ms = new MsClient(new HttpClient(handler), new FakeCredential());
        var def = Catalog.Get("intune_sync_device");
        var p = def.Validate(El(new { managed_device_id = Managed }));
        var facts = await def.Resolve!(new ResolveContext(null!, ms, new Settings(), Now), p, TestContext.Current.CancellationToken);
        Assert.Equal([Managed], facts.UnresolvedDevices);
        Assert.Equal(Managed, facts.Data!["managed_device_id"]!.GetValue<string>());
        Assert.Contains(facts.Notes!, n => n.Contains("only partly resolved"));
        var policy = new Policy { AutoApprove = ["intune_sync_device"], ProtectedDevices = ["dc01.contoso.local"] };
        // Still a host-label match where the name is known, so dc01 is refused...
        Assert.Equal(Outcome.Reject, PolicyEngine.Evaluate(def, p, Incident, policy, actionFacts: facts).Outcome);
        // ...and a device whose names are partly unknown never runs on its own.
        var other = new ActionFacts(DeviceAliases: new Dictionary<string, string[]> { [Managed] = [Managed, Aad, "ws-9"] }, UnresolvedDevices: [Managed]);
        var d = PolicyEngine.Evaluate(def, p, Incident, policy, actionFacts: other);
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains("checked by id only"));
    }

    [Fact]
    public async Task Resolver_fails_closed_when_a_lookup_throws()
    {
        // Defender answers 403 (a missing permission): the lookup throws, and the device is unresolved, not "clean".
        var ms = new MsClient(new HttpClient(new Status(HttpStatusCode.Forbidden)), new FakeCredential());
        var def = Catalog.Get("intune_sync_device");
        var facts = await def.Resolve!(new ResolveContext(null!, ms, new Settings(), Now), def.Validate(El(new { machine_id = Mde })), TestContext.Current.CancellationToken);
        Assert.Equal([Mde], facts.UnresolvedDevices);
        Assert.Contains(facts.Notes!, n => n.Contains("device lookup failed"));
    }

    private sealed class Status(HttpStatusCode code) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(code) { Content = new StringContent("""{"error":{"message":"denied"}}""", Encoding.UTF8, "application/json") });
    }

    // ── exposure scoring ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Prioritisation_puts_exploited_internet_facing_and_incident_devices_first()
    {
        var rows = JsonDocument.Parse("""
            [
              { "CveId": "CVE-2025-0001", "DeviceId": "d1", "DeviceName": "ws-1.contoso.com", "Severity": "Critical", "CvssScore": "9.8", "IsExploitAvailable": false, "IsInternetFacing": false, "AssetValue": "Normal" },
              { "CveId": "CVE-2025-0001", "DeviceId": "d2", "DeviceName": "ws-2.contoso.com", "Severity": "Critical", "CvssScore": "9.8", "IsExploitAvailable": false, "IsInternetFacing": false, "AssetValue": "Normal" },
              { "CveId": "CVE-2024-3400", "DeviceId": "d3", "DeviceName": "edge.contoso.com", "Severity": "High", "CvssScore": "8.1", "IsExploitAvailable": true, "IsInternetFacing": true, "AssetValue": "High" },
              { "CveId": "CVE-2023-0002", "DeviceId": "d4", "DeviceName": "ws-4.contoso.com", "Severity": "Medium", "IsExploitAvailable": false, "IsInternetFacing": false, "AssetValue": "Normal" }
            ]
            """).RootElement.EnumerateArray().ToList();
        var ranked = ExposureService.Rank(rows, new HashSet<string> { "CVE-2024-3400" }, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "ws-4" }, null, 10);
        Assert.Equal("CVE-2024-3400", ranked[0].Id);
        Assert.True(ranked[0].KnownExploited);
        Assert.Contains(ranked[0].Reasons, r => r.Contains("KEV"));
        Assert.Equal(1, ranked[0].InternetFacingDevices);
        var medium = ranked.Single(x => x.Id == "CVE-2023-0002");
        Assert.Equal(1, medium.InOpenIncidents);
        Assert.True(medium.TopDevices[0].InOpenIncident);
        Assert.Equal(2, ranked.Single(x => x.Id == "CVE-2025-0001").Devices);
        Assert.Single(ExposureService.Rank(rows, new HashSet<string>(), new HashSet<string>(), new HashSet<string> { "CVE-2025-0001" }, 10));
    }

    [Fact]
    public void Score_is_capped_and_explained()
    {
        var (score, reasons) = ExposureService.Score("Critical", 10, true, true, 5000, 10, 10, 10);
        Assert.Equal(100, score);
        Assert.Equal(5, reasons.Length);
        Assert.True(ExposureService.Score("Low", null, false, false, 1, 0, 0, 0).Score < ExposureService.Score("Low", null, true, false, 1, 0, 0, 0).Score);
    }

    [Fact]
    public void Attack_path_kql_is_board_built_and_passes_the_guards()
    {
        var kql = ExposureService.AttackPathsKql(true, true, 999);
        Assert.Contains("take 50", kql);
        Enrichment.ValidateKql(kql, "P1D");
        Enrichment.ValidateKql(ExposureService.PrioritiesKql, "P1D");
    }

    // ── permissions and contracts ──────────────────────────────────────────────────────────────

    [Fact]
    public void New_kinds_have_permissions_and_tools_are_registered()
    {
        foreach (var k in new[] { "create_detection_rule", "disable_detection_rule", "intune_sync_device", "intune_update_defender_signatures", "intune_expedite_quality_update" })
            Assert.True(Permissions.WriteFor.ContainsKey(k), k);
        Assert.Equal("CustomDetection.ReadWrite.All", Permissions.WriteFor["create_detection_rule"].Name);
        Assert.Equal("WindowsUpdates.ReadWrite.All", Permissions.WriteFor["intune_expedite_quality_update"].Name);
        foreach (var t in new[] { Tools.BacktestDetection, Tools.ListExposureRecommendations, Tools.GetAttackPaths, Tools.PrioritizeExposures })
            Assert.Equal("hunter", Tools.Get(t).Role);
        var schema = Blueboard.Api.Mcp.McpSchemas.All()[Tools.BacktestDetection];
        Assert.Equal(30, schema["properties"]!["lookback_days"]!["maximum"]!.GetValue<long>());
    }

    [Fact]
    public void Arm_origin_is_pinned_and_demo_mode_maps_it_to_the_mock()
    {
        Assert.Equal("https://management.azure.com/subscriptions/x", MsClient.BuildUri(MsApi.Arm, "/subscriptions/x").ToString());
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(MsApi.Arm, "https://evil.example/x"));
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(MsApi.Arm, "/subscriptions/../x"));
        var demo = MsOrigins.For(new Settings { DemoMode = true, DevAuth = true, GraphBaseUrl = "http://mock:8080", DefenderBaseUrl = "http://mock:8080" });
        Assert.Equal("http://mock:8080", demo.Arm);
    }

    /// <summary>Answers scripted (method, path-prefix) routes in any order and 404s everything else.</summary>
    private sealed class Scripted(params (string Method, string Path, string Body)[] routes) : HttpMessageHandler
    {
        public List<string> Seen { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            var query = request.RequestUri.Query.TrimStart('?');
            Seen.Add(query.Length == 0 ? $"{request.Method} {path}" : $"{request.Method} {path}?{Uri.UnescapeDataString(query)}");
            foreach (var (m, p, body) in routes)
                if (request.Method.Method == m && path == p)
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("""{"error":{"message":"not found"}}""", Encoding.UTF8, "application/json") });
        }
    }
}
