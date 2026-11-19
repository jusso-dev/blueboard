using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Intel;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Offline parsing tests over fixtures recorded from the live feeds on 19-11-2026, plus the KQL, STIX and policy builders.</summary>
public class IntelTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 19, 12, 0, 0, TimeSpan.Zero);

    // ── pwn.watch ──────────────────────────────────────────────────────────────────────────────
    [Fact]
    public void Pwnwatch_incidents_parse_with_cves_patch_status_and_fixed_versions()
    {
        var r = PwnWatchParser.Incidents(Fixtures.Read("pwnwatch/incidents.json"), Now);
        Assert.Equal(1, r.Skipped); // the fixture has one malformed item (no slug)
        Assert.Equal(new DateTimeOffset(2026, 11, 8, 20, 22, 39, 494, TimeSpan.Zero), r.DataAsOf);
        var android = r.Records.Single(x => x.Keys.Contains(("cve", "CVE-2026-58868")));
        Assert.Equal("patched", android.Data["patch_status"]!.GetValue<string>());
        Assert.NotEmpty(android.Data["fixed_versions"]!.AsArray());
        Assert.StartsWith("https://pwn.watch/i/", android.Url);
        Assert.Equal(PwnWatchParser.IncidentsUrl, android.SourceUrl);
        Assert.Contains(("tag", "android"), android.Keys);
    }

    [Fact]
    public void Pwnwatch_ignores_unknown_fields_skips_examples_and_unsafe_links()
    {
        const string json = """
            {"generatedAt":"2026-11-08T00:00:00Z","incidents":[
              {"slug":"a","title":"A","url":"javascript:alert(1)","cveIds":["cve-2026-1234","nope"],"brandNewField":{"x":1}},
              {"slug":"b","title":"B","isExample":true},
              {"slug":"../c","title":"C"},
              "not an object"
            ]}
            """;
        var r = PwnWatchParser.Incidents(json, Now);
        var a = Assert.Single(r.Records);
        Assert.Equal("https://pwn.watch/i/a", a.Url);
        Assert.Equal(["CVE-2026-1234"], a.Data["cve_ids"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Equal(2, r.Skipped);
    }

    [Fact]
    public void Pwnwatch_change_hash_is_stable_across_replays()
    {
        var (first, _) = PwnWatchParser.Changes(Fixtures.Read("pwnwatch/changes.json"));
        var (again, _) = PwnWatchParser.Changes(Fixtures.Read("pwnwatch/changes.json"));
        Assert.NotEmpty(first);
        Assert.Equal(first.Select(c => c.Hash), again.Select(c => c.Hash));
        Assert.Equal(PwnWatchParser.ChangeHash("x", "2026-11-08", "t"), PwnWatchParser.ChangeHash("x", "2026-11-08", "t"));
        Assert.NotEqual(PwnWatchParser.ChangeHash("x", "2026-11-08", "t"), PwnWatchParser.ChangeHash("x", "2026-11-09", "t"));
    }

    [Fact]
    public void Pwnwatch_agent_brief_is_read_from_the_incident_file() =>
        Assert.StartsWith("# Security brief", PwnWatchParser.AgentBrief(Fixtures.Read("pwnwatch/incident-android-november-2026-security-bulletin-cve-2026-58868.json")));

    [Fact]
    public void Freshness_warns_after_three_days()
    {
        var f = IntelService.Freshness(new DateTimeOffset(2026, 11, 8, 20, 22, 39, TimeSpan.Zero), Now);
        Assert.Equal("pwn.watch data from 8 Nov 2026 (10 days old)", f["freshness"]!.GetValue<string>());
        Assert.True(f["stale"]!.GetValue<bool>());
        Assert.False(IntelService.Freshness(Now.AddDays(-2), Now)["stale"]!.GetValue<bool>());
    }

    // ── KEV, EPSS, NVD, OSV ──────────────────────────────────────────────────────────────────────
    [Fact]
    public void Kev_parses_log4shell_with_dates_action_and_ransomware()
    {
        var r = KevParser.Parse(Fixtures.Read("kev.json"), Now);
        var log4j = r.Records.Single(x => x.Key == "CVE-2021-44228");
        Assert.Equal("2021-12-10", log4j.Data["date_added"]!.GetValue<string>());
        Assert.Equal("2021-12-24", log4j.Data["due_date"]!.GetValue<string>());
        Assert.StartsWith("For all affected software", log4j.Data["required_action"]!.GetValue<string>());
        Assert.True(log4j.Data["known_ransomware"]!.GetValue<bool>());
        Assert.Contains(("tag", "cisa-kev"), log4j.Keys);
    }

    [Fact]
    public void Epss_parses_scores_and_caches_misses()
    {
        var recs = EpssParser.Parse(Fixtures.Read("epss.json"), ["CVE-2021-44228", "CVE-2099-0001"], "u", Now);
        var hit = recs.Single(r => r.Key == "CVE-2021-44228");
        Assert.True(hit.Found);
        Assert.Equal(0.99999, hit.Data["epss"]!.GetValue<double>(), 5);
        Assert.False(recs.Single(r => r.Key == "CVE-2099-0001").Found);
    }

    [Fact]
    public void Epss_batches_250_cves_into_3_requests()
    {
        var cves = Enumerable.Range(1, 250).Select(i => $"CVE-2026-{i:00000}").ToList();
        var batches = cves.Chunk(EpssParser.BatchSize).Select(EpssParser.Url).ToList();
        Assert.Equal(3, batches.Count);
        Assert.All(batches, u => Assert.True(u.Length < 2000));
    }

    [Fact]
    public void Nvd_parses_cvss_cwe_and_carries_the_notice()
    {
        var r = NvdParser.Parse(Fixtures.Read("nvd/CVE-2021-44228.json"), "CVE-2021-44228", Now);
        Assert.True(r.Found);
        Assert.Equal(10.0, r.Data["cvss"]!["score"]!.GetValue<double>());
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", r.Data["cvss"]!["vector"]!.GetValue<string>());
        Assert.Contains("CWE-917", r.Data["cwes"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Equal(Sources.NvdNotice, r.Data["notice"]!.GetValue<string>());
        Assert.False(NvdParser.Parse("""{"vulnerabilities":[]}""", "CVE-2099-0001", Now).Found);
    }

    [Fact]
    public void Osv_ghsa_fixture_shows_fixed_versions()
    {
        var r = OsvParser.Parse(Fixtures.Read("osv/GHSA-jfh8-c2jp-5v3q.json"), "GHSA-jfh8-c2jp-5v3q", Now);
        var core = r.Data["packages"]!.AsArray().First(p => p!["name"]!.GetValue<string>() == "org.apache.logging.log4j:log4j-core")!;
        Assert.Contains("2.15.0", core["fixed"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Contains(("cve", "CVE-2021-44228"), r.Keys);
        Assert.True(OsvParser.HasFixedPackages(r));
        // The CVE record only has git ranges, so the service follows its GHSA alias for versions.
        Assert.False(OsvParser.HasFixedPackages(OsvParser.Parse(Fixtures.Read("osv/CVE-2021-44228.json"), "CVE-2021-44228", Now)));
    }

    // ── indicators, KQL ────────────────────────────────────────────────────────────────────────
    [Theory]
    [InlineData("cve-2021-44228", "cve", "CVE-2021-44228")]
    [InlineData("203.0.113.5", "ip", "203.0.113.5")]
    [InlineData("Bad.Example.", "domain", "bad.example")]
    [InlineData("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("GHSA-JFH8-C2JP-5V3Q", "ghsa", "GHSA-jfh8-c2jp-5v3q")]
    [InlineData("https://bad.example/x?a=1", "url", "https://bad.example/x?a=1")]
    public void Keys_are_classified_and_normalised(string raw, string kind, string value) =>
        Assert.Equal(new IntelKey(kind, value), Indicators.Parse(raw));

    [Theory]
    [InlineData("CVE-21-1")]
    [InlineData("\") | take 1 //")]
    [InlineData("1.2.3")]
    public void Junk_keys_are_refused(string raw) => Assert.Throws<BoardException>(() => Indicators.Parse(raw));

    [Fact]
    public void Cve_ids_are_found_in_text() =>
        Assert.Equal(["CVE-2021-44228", "CVE-2024-3400"], Indicators.CvesIn("see cve-2021-44228 and CVE-2024-3400, again CVE-2021-44228; not CVE-21-1"));

    [Fact]
    public void Exposure_kql_accepts_only_valid_cve_ids()
    {
        var q = Kql.Exposure(["cve-2021-44228", "CVE-2024-3400"]);
        Assert.Contains("dynamic([\"CVE-2021-44228\", \"CVE-2024-3400\"])", q);
        Assert.StartsWith("DeviceTvmSoftwareVulnerabilities", q);
        Assert.Throws<BoardException>(() => Kql.Exposure(["CVE-2021-44228\"]) | union (SigninLogs"]));
        Assert.Throws<BoardException>(() => Kql.Exposure([]));
        Assert.Throws<BoardException>(() => Kql.Exposure(Enumerable.Range(1, 101).Select(i => $"CVE-2026-{i:0000}").ToList()));
    }

    [Fact]
    public void Sentinel_kql_escapes_values_and_uses_the_new_table()
    {
        var q = Kql.SentinelIndicators([new IntelKey("url", "https://bad.example/a'b"), new IntelKey("ip", "203.0.113.5")]);
        Assert.StartsWith("ThreatIntelIndicators", q);
        Assert.DoesNotContain("ThreatIntelligenceIndicator", q);
        Assert.Contains("\"https://bad.example/a'b\"", q);
        foreach (var col in new[] { "ObservableValue", "IsActive", "Revoked", "ValidUntil", "ObservableKey", "Confidence", "SourceSystem", "Tags" }) Assert.Contains(col, q);
        Assert.Throws<BoardException>(() => Kql.SentinelIndicators([new IntelKey("domain", "x\" or 1==1")]));
        Assert.Equal("\"a\\\\b\\\"c\"", Kql.Literal("a\\b\"c"));
    }

    [Fact]
    public void Microsoft_fixtures_shape_into_cards()
    {
        using var s = JsonDocument.Parse(Fixtures.Read("sentinel/indicators.json"));
        var m = MicrosoftIntel.SentinelMatches(s.RootElement.GetProperty("results").EnumerateArray());
        Assert.Equal(85, m[0]!["confidence"]!.GetValue<double>());
        Assert.Equal("Premium Microsoft Defender Threat Intelligence", m[0]!["source_system"]!.GetValue<string>());
        using var e = JsonDocument.Parse(Fixtures.Read("exposure/vulnerabilities.json"));
        var row = MicrosoftIntel.ExposureRows(e.RootElement.GetProperty("results").EnumerateArray()).Single(r => r.Cve == "CVE-2021-44228");
        Assert.Equal(14, row.Devices);
        Assert.True(row.DeviceNames.Length <= 20);
        using var v = JsonDocument.Parse(Fixtures.Read("msti/vulnerability-CVE-2021-44228.json"));
        Assert.True(MicrosoftIntel.MstiVulnerability(v.RootElement)["active_exploits_observed"]!.GetValue<bool>());
    }

    // ── watches, compare ───────────────────────────────────────────────────────────────────────
    [Fact]
    public void Watches_match_tags_and_whole_word_products()
    {
        Watch W(string k, string v) => new(Guid.NewGuid(), k, v, true, "manual", null, null);
        var rec = new Watchable("Microsoft Entra device registration elevation of privilege", "", ["microsoft", "entra"], ["CVE-2026-109469"], ["Microsoft Entra ID"]);
        Assert.True(Watches.Matches(W("tag", "microsoft"), rec));
        Assert.True(Watches.Matches(W("product", "entra id"), rec));
        Assert.True(Watches.Matches(W("cve", "CVE-2026-109469"), rec));
        Assert.False(Watches.Matches(W("product", "entr"), rec));
        Assert.False(Watches.Matches(W("tag", "cisa-kev"), rec));
        Assert.Equal("CVE-2024-3400", Watches.Normalise("cve", " cve-2024-3400 "));
        Assert.Throws<BoardException>(() => Watches.Normalise("keyword", "ab"));
    }

    [Fact]
    public void Compare_says_agree_and_differ()
    {
        IntelCard C(string src, string name, string? sev, JsonObject data) => new(src, name, "found", "a", null, Now, null, sev, data);
        var cards = new[]
        {
            C(Sources.Kev, "CISA KEV", "known exploited", new JsonObject { ["date_added"] = "2021-12-10" }),
            C(Sources.Nvd, "NVD", "critical", new JsonObject { ["published"] = "2021-12-10T10:15:09" }),
            C(Sources.Msti, "Microsoft TI", "high", new JsonObject { ["active_exploits_observed"] = false, ["published"] = "2021-12-11T00:00:00Z" }),
            new IntelCard(Sources.Epss, "FIRST EPSS", "not_checked", "a", null, null, Reason: "off"),
        };
        var (agree, differ) = IntelService.Compare("CVE-2021-44228", cards);
        Assert.Contains(differ, d => d.StartsWith("Exploitation reported by CISA KEV, not by Microsoft TI"));
        Assert.Contains(differ, d => d.StartsWith("Severity differs"));
        Assert.Contains(differ, d => d.StartsWith("Dates differ"));
        var (none, _) = IntelService.Compare("CVE-2099-0001", [new IntelCard(Sources.Kev, "CISA KEV", "not_checked", "a", null, null)]);
        Assert.Equal(["No source was checked for CVE-2099-0001."], none);
    }

    [Fact]
    public void Board_posts_from_intel_cannot_mention_anyone() =>
        Assert.Empty(Board.BoardService.ParseMentions(IntelService.Clean("ping @analyst\nnow `code`")));

    // ── settings ───────────────────────────────────────────────────────────────────────────────
    [Fact]
    public void Everything_is_off_by_default() => Assert.False(TiSettings.From(_ => null, inAzure: false).AnyEnabled);

    [Fact]
    public void Cvewatch_flag_is_refused_at_startup()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => TiSettings.From(k => k == "TI_CVEWATCH_ENABLED" ? "true" : null, inAzure: false));
        Assert.Equal("cve.watch is unavailable, see docs/ti/sources.md", ex.Message);
    }

    [Fact]
    public void Fixture_mode_is_refused_in_azure() =>
        Assert.Throws<InvalidOperationException>(() => TiSettings.From(k => k == "TI_FIXTURES_DIR" ? "/tmp" : null, inAzure: true));

    // ── STIX and publish_ti_indicator (#20) ─────────────────────────────────────────────────────
    [Theory]
    [InlineData("ip", "203.0.113.5", "[ipv4-addr:value = '203.0.113.5']")]
    [InlineData("ip", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']")]
    [InlineData("domain", "Bad.Example", "[domain-name:value = 'bad.example']")]
    [InlineData("sha256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "[file:hashes.'SHA-256' = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']")]
    [InlineData("url", "https://bad.example/it's", "[url:value = 'https://bad.example/it\\'s']")]
    public void Stix_patterns_are_built_and_escaped(string kind, string value, string pattern) =>
        Assert.Equal(pattern, Stix.Pattern(kind, value));

    [Theory]
    [InlineData("ip", "203.0.113.5'] OR [x:y = 'z")]
    [InlineData("domain", "bad.example' OR '1")]
    [InlineData("sha256", "abc")]
    [InlineData("user", "ana@contoso.com")]
    public void Stix_pattern_rejects_values_that_do_not_fit_the_kind(string kind, string value) =>
        Assert.Throws<BoardException>(() => Stix.Pattern(kind, value));

    private static JsonObject PublishParams(string value = "cdn-update-check.example.net") => Catalog.Get("publish_ti_indicator").Validate(JsonSerializer.SerializeToElement(new
    {
        kind = "domain", value, confidence = 80, valid_days = 30, tlp = "amber", description = "Phishing payload host confirmed on the board",
    }));

    [Fact]
    public void Stix_upload_request_is_complete()
    {
        var actionId = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var req = Stix.UploadRequest(PublishParams(), new ActionContext(actionId, "90210", Guid.Empty, "agent", "analyst", "j",
            new TiSettings { SentinelWorkspaceId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", BoardWebUrl = "https://board.example" }, Now));
        Assert.Equal("blueboard", req["body"]!["sourcesystem"]!.GetValue<string>());
        var ind = req["body"]!["stixobjects"]!.AsArray()[1]!;
        Assert.Equal("indicator", ind["type"]!.GetValue<string>());
        Assert.Equal("2.1", ind["spec_version"]!.GetValue<string>());
        Assert.Equal("[domain-name:value = 'cdn-update-check.example.net']", ind["pattern"]!.GetValue<string>());
        Assert.Equal(Stix.IndicatorId(actionId), ind["id"]!.GetValue<string>());
        Assert.Equal(Stix.IdentityId, ind["created_by_ref"]!.GetValue<string>());
        Assert.Equal("2026-12-19T12:00:00.000Z", ind["valid_until"]!.GetValue<string>());
        Assert.Equal(80, ind["confidence"]!.GetValue<int>());
        Assert.Equal("https://board.example/incidents/00000000-0000-0000-0000-000000000000", ind["external_references"]![0]!["url"]!.GetValue<string>());
        Assert.Matches("^indicator--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", ind["id"]!.GetValue<string>());
        Assert.Throws<BoardException>(() => Stix.UploadRequest(PublishParams(), new ActionContext(actionId, null, null, "a", null, "j", new TiSettings(), Now)));
    }

    [Fact]
    public void Publish_params_are_validated()
    {
        var def = Catalog.Get("publish_ti_indicator");
        Assert.True(def.Destructive);
        Assert.Throws<BoardException>(() => def.Validate(JsonSerializer.SerializeToElement(new { kind = "domain", value = "bad.example", confidence = 101, description = "long enough text" })));
        Assert.Throws<BoardException>(() => def.Validate(JsonSerializer.SerializeToElement(new { kind = "domain", value = "bad.example", confidence = 50, valid_days = 91, description = "long enough text" })));
        Assert.Throws<BoardException>(() => def.Validate(JsonSerializer.SerializeToElement(new { kind = "ip", value = "bad.example", confidence = 50, description = "long enough text" })));
    }

    private static IncidentContext Incident(params string[] malicious) =>
        new("90210", JsonDocument.Parse("""{"alerts":[{"evidence":[{"@odata.type":"#microsoft.graph.security.urlEvidence","url":"https://cdn-update-check.example.net/payload.ps1"}]}]}""").RootElement,
            malicious.ToHashSet());

    [Fact]
    public void Publish_without_a_matching_malicious_ioc_is_rejected()
    {
        var def = Catalog.Get("publish_ti_indicator");
        Assert.Equal(Outcome.Reject, PolicyEngine.Evaluate(def, PublishParams(), Incident(), new Policy()).Outcome);
        Assert.Equal(Outcome.Reject, PolicyEngine.Evaluate(def, PublishParams(), null, new Policy()).Outcome);
        var ok = PolicyEngine.Evaluate(def, PublishParams(), Incident("domain:cdn-update-check.example.net"), new Policy());
        Assert.Equal(Outcome.NeedsApproval, ok.Outcome);
    }

    [Fact]
    public void Publish_is_never_auto_approved_and_protected_indicators_are_rejected()
    {
        var def = Catalog.Get("publish_ti_indicator");
        var inc = Incident("domain:cdn-update-check.example.net", "domain:contoso.com");
        Assert.Equal(Outcome.NeedsApproval, PolicyEngine.Evaluate(def, PublishParams(), inc, new Policy { AutoApprove = ["publish_ti_indicator"] }).Outcome);
        Assert.Equal(Outcome.Reject, PolicyEngine.Evaluate(def, PublishParams("contoso.com"), inc, new Policy { ProtectedIndicators = ["contoso.com"] }).Outcome);
    }

    [Fact]
    public void Sentinel_upload_token_only_goes_to_the_exact_origin()
    {
        Assert.Equal("api.ti.sentinel.azure.com", Graph.MsClient.BuildUri(Graph.MsApi.SentinelTi, "/workspaces/x/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview").Host);
        Assert.Throws<InvalidOperationException>(() => Graph.MsClient.BuildUri(Graph.MsApi.SentinelTi, "https://api.ti.sentinel.azure.com.evil.example/x"));
        Assert.Throws<InvalidOperationException>(() => Graph.MsClient.BuildUri(Graph.MsApi.SentinelTi, "https://graph.microsoft.com/v1.0/me"));
    }
}
