using Blueboard.Contracts;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Blueboard.Api.Intel;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>
/// Threat intel on a real database, with every source served from the recorded fixtures (no network, no tenant).
/// </summary>
public sealed class IntelTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static string FixturesDir => Path.Combine(AppContext.BaseDirectory, "Fixtures", "ti");

    private static TiSettings AllOn => new()
    {
        PwnWatch = true, Kev = true, Epss = true, Nvd = true, Osv = true, Sentinel = true, Msti = true, Exposure = true,
        FixturesDir = FixturesDir, SentinelWorkspaceId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    };

    private IntelService Intel(TiSettings ti, out IntelStore store)
    {
        var settings = t.Settings with { Ti = ti };
        store = new IntelStore(t.Db);
        var board = new BoardService(t.Db, t.Audit, settings);
        var enrich = new Enrichment(t.Db, t.Audit, board, t.Ms);
        return new IntelService(t.Db, store, new TiFetcher(new PgFetchCache(t.Db), ti), new MicrosoftIntel(enrich, t.Ms, settings),
            board, new Search(t.Db, board), t.System, settings, NullLogger<IntelService>.Instance);
    }

    private Task<long> IntelPosts() => t.ScalarAsync("select count(*) from messages m join channels c on c.id = m.channel_id where c.name = 'intel' and m.type = 'finding'");

    [DbFact]
    public async Task With_every_source_off_nothing_is_checked_and_index_names_the_flags()
    {
        var intel = Intel(new TiSettings(), out _);
        var me = await t.As("analyst");
        Assert.Empty((Dictionary<string, string>)await intel.RunFeedsAsync(Ct));
        var l = await intel.LookupAsync(me, "CVE-2021-44228", Ct);
        Assert.All(l.Cards, c => Assert.Equal("not_checked", c.Status));
        Assert.Contains(l.Cards, c => c.Reason == "off: set TI_KEV_ENABLED=true to turn it on");
        Assert.Contains(l.Cards, c => c.Source == Sources.CveWatch && c.Reason!.StartsWith("unavailable"));
        var index = JsonSerializer.SerializeToElement(await intel.IndexAsync(me, Ct), Json.Options);
        Assert.False(index.GetProperty("any_enabled").GetBoolean());
        Assert.Contains(index.GetProperty("sources").EnumerateArray(), s => s.GetProperty("flag").GetString() == "TI_PWNWATCH_ENABLED");
    }

    [DbFact]
    public async Task Lookup_log4shell_returns_a_card_from_every_enabled_source()
    {
        var intel = Intel(AllOn, out _);
        await intel.RunFeedsAsync(Ct);
        var l = await intel.LookupAsync(await t.As("analyst"), "cve-2021-44228", Ct);
        Assert.Equal("CVE-2021-44228", l.Key);
        foreach (var src in new[] { Sources.PwnWatch, Sources.Kev, Sources.Epss, Sources.Nvd, Sources.Osv, Sources.Msti, Sources.Exposure })
        {
            var c = Assert.Single(l.Cards, c => c.Source == src);
            Assert.NotEqual("not_checked", c.Status);
            Assert.NotNull(c.RetrievedAt);
            Assert.False(string.IsNullOrEmpty(c.Url));
            Assert.StartsWith("Source:", c.Attribution);
        }
        var kev = l.Cards.Single(c => c.Source == Sources.Kev);
        Assert.Equal("found", kev.Status);
        Assert.Equal("2021-12-24", kev.Data!["due_date"]!.GetValue<string>());
        Assert.Equal("not_found", l.Cards.Single(c => c.Source == Sources.PwnWatch).Status); // in the fixture, pwn.watch has no Log4Shell incident
        Assert.Contains("NVD", l.Cards.Single(c => c.Source == Sources.Nvd).Attribution);
        var osv = l.Cards.Single(c => c.Source == Sources.Osv);
        Assert.Equal("GHSA-jfh8-c2jp-5v3q", osv.Data!["packages_from"]!.GetValue<string>());
        var exposure = l.Cards.Single(c => c.Source == Sources.Exposure);
        Assert.Equal("Present on 14 device(s) (1 in open incidents)", exposure.Title);
        Assert.NotEmpty(l.Agree.Concat(l.Differ));
    }

    [DbFact]
    public async Task Pwnwatch_android_cve_has_patch_status_and_fixed_versions()
    {
        var intel = Intel(AllOn with { Kev = false }, out _);
        await intel.RunPwnWatchAsync(Ct);
        var card = (await intel.LookupAsync(await t.As("agent"), "CVE-2026-58868", Ct)).Cards.Single(c => c.Source == Sources.PwnWatch);
        Assert.Equal("found", card.Status);
        Assert.Equal("patched", card.Data!["patch_status"]!.GetValue<string>());
        Assert.NotEmpty(card.Data!["fixed_versions"]!.AsArray());
        Assert.True(card.Data!["stale"]!.GetValue<bool>()); // fixture generatedAt is 8 Nov 2026
        Assert.Equal("Source: pwn.watch", card.Attribution);
    }

    [DbFact]
    public async Task Watched_pwnwatch_change_posts_once_and_replay_posts_nothing()
    {
        var intel = Intel(new TiSettings { PwnWatch = true, FixturesDir = FixturesDir }, out var store);
        await intel.RunPwnWatchAsync(Ct); // first run: baseline, nothing posted
        var before = await IntelPosts();
        var change = new PwnChange(PwnWatchParser.ChangeHash("microsoft-entra-device-registration-eop-cve-2026-109469", "2026-11-19", "Exploit published"),
            "microsoft-entra-device-registration-eop-cve-2026-109469", null, "high", "live", null, "2026-11-19", "Exploit published", null, null);
        var (posted, _) = await intel.PostPwnChangesAsync([change], baseline: false, Ct);
        Assert.Equal(1, posted);
        Assert.Equal(before + 1, await IntelPosts());
        Assert.Equal(0, (await intel.PostPwnChangesAsync([change], baseline: false, Ct)).Posted);
        var update = change with { Hash = PwnWatchParser.ChangeHash(change.Incident, "2026-11-20", "Fixed"), Title = "Fixed", Date = "2026-11-20" };
        await intel.PostPwnChangesAsync([update], baseline: false, Ct);
        var msgs = await t.Board.ReadFeedAsync(new FeedQuery(Channel: "intel", Limit: 200), Ct);
        var root = msgs.Messages.Single(m => m.Body.Contains("Exploit published"));
        var reply = msgs.Messages.Single(m => m.Body.Contains("> Fixed"));
        Assert.Equal(root.Id, reply.ParentId); // updates go in the same thread
        Assert.Contains("Source: pwn.watch", root.Body);
        Assert.Contains("https://pwn.watch/i/", root.Body);
        Assert.Equal(Sources.PwnWatch, root.Payload!.Value.GetProperty("source").GetString());
        // Replaying the recorded feed posts nothing new.
        await store.SetStatusAsync(Sources.PwnWatch, "ok", null, null, Ct);
        await using (var c = t.Db.Command("delete from kv_state where key like 'ti.parsed.%'")) await c.ExecuteNonQueryAsync(Ct);
        var count = await IntelPosts();
        await intel.RunPwnWatchAsync(Ct);
        Assert.Equal(count, await IntelPosts());
    }

    [DbFact]
    public async Task Second_feed_run_inside_the_ttl_makes_no_request()
    {
        var store = new IntelStore(t.Db);
        var settings = t.Settings with { Ti = new TiSettings { Kev = true } };
        var calls = 0;
        var handler = new CountingHandler(() => { calls++; return Fixture("kev.json"); });
        var board = new BoardService(t.Db, t.Audit, settings);
        var intel = new IntelService(t.Db, store, new TiFetcher(new PgFetchCache(t.Db), settings.Ti, handler), new MicrosoftIntel(new Enrichment(t.Db, t.Audit, board, t.Ms), t.Ms, settings),
            board, new Search(t.Db, board), t.System, settings, NullLogger<IntelService>.Instance);
        await using (var c = t.Db.Command("delete from ti_fetch_cache")) await c.ExecuteNonQueryAsync(Ct);
        await intel.RunKevAsync(Ct);
        await intel.RunKevAsync(Ct);
        Assert.Equal(1, calls);
        Assert.NotNull(await store.GetAsync(Sources.Kev, "CVE-2021-44228", Ct));
    }

    [DbFact]
    public async Task Epss_batches_and_caches_for_a_day()
    {
        var store = new IntelStore(t.Db);
        var settings = t.Settings with { Ti = new TiSettings { Epss = true } };
        var urls = new List<string>();
        var handler = new CountingHandler(() => Fixture("epss.json"), urls);
        var board = new BoardService(t.Db, t.Audit, settings);
        var intel = new IntelService(t.Db, store, new TiFetcher(new PgFetchCache(t.Db), settings.Ti, handler), new MicrosoftIntel(new Enrichment(t.Db, t.Audit, board, t.Ms), t.Ms, settings),
            board, new Search(t.Db, board), t.System, settings, NullLogger<IntelService>.Instance);
        var cves = Enumerable.Range(1, 250).Select(i => $"CVE-2025-{i:00000}").ToList();
        var (_, first) = await intel.EpssAsync(cves, Ct);
        var (_, second) = await intel.EpssAsync(cves, Ct);
        Assert.Equal(3, first);
        Assert.Equal(0, second);
        Assert.Equal(3, urls.Count);
    }

    [DbFact]
    public async Task Exposure_returns_capped_names_and_open_incident_count()
    {
        var intel = Intel(AllOn, out _);
        var res = await intel.ExposureAsync(await t.As("agent"), ["CVE-2021-44228", "CVE-2024-3400"], Ct);
        var log4j = res.Single(r => r.Cve == "CVE-2021-44228");
        Assert.Equal(14, log4j.Devices);
        Assert.True(log4j.DeviceNames.Count <= 20);
        Assert.Equal(1, log4j.InOpenIncidents); // the sample incident's device
        Assert.Equal(0, res.Single(r => r.Cve == "CVE-2024-3400").Devices);
        var reader = await t.As("reader");
        await Assert.ThrowsAsync<BoardException>(() => intel.ExposureAsync(reader, ["CVE-2021-44228"], Ct));
        await Assert.ThrowsAsync<BoardException>(() => intel.ExposureAsync(null, ["CVE-2021-44228') | union x"], Ct));
    }

    [DbFact]
    public async Task Sentinel_match_for_the_phishing_url_and_one_auto_enrich_finding()
    {
        var intel = Intel(AllOn, out _);
        var l = await intel.LookupAsync(await t.As("analyst"), "https://cdn-update-check.example.net/payload.ps1", Ct);
        var card = l.Cards.Single(c => c.Source == Sources.Sentinel);
        Assert.Equal("found", card.Status);
        Assert.Equal(85, card.Data!["matches"]![0]!["confidence"]!.GetValue<double>());
        Assert.Equal("malicious", l.Cards.Single(c => c.Source == Sources.Msti).Severity);

        var ingest = new Ingest(t.Db, t.Board, t.Ms, t.System, t.Settings);
        var inc = JsonSerializer.SerializeToElement(new Dictionary<string, object>
        {
            ["id"] = "77001", ["displayName"] = "Phishing", ["severity"] = "medium", ["status"] = "active",
            ["alerts"] = new object[] { new Dictionary<string, object> { ["id"] = "a1", ["evidence"] = new object[]
            {
                new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.urlEvidence", ["url"] = "https://cdn-update-check.example.net/payload.ps1" },
            } } },
        });
        await ingest.UpsertAsync(inc, Ct);
        Assert.True(await intel.AutoEnrichSentinelAsync(Ct) >= 1);
        Assert.Equal(0, await intel.AutoEnrichSentinelAsync(Ct));
        var id = (await t.Board.ResolveIncidentAsync("77001", Ct))!.Value;
        var thread = await t.Board.ReadFeedAsync(new FeedQuery(Incident: id.ToString()), Ct);
        Assert.Single(thread.Messages, m => m.Type == "finding" && m.Body.Contains("Sentinel threat intelligence matches"));
    }

    [DbFact]
    public async Task Tenant_sources_need_board_hunt()
    {
        var intel = Intel(AllOn, out _);
        var l = await intel.LookupAsync(await t.As("reader"), "CVE-2021-44228", Ct);
        Assert.Equal("needs the Board.Hunt role", l.Cards.Single(c => c.Source == Sources.Exposure).Reason);
    }

    [DbFact]
    public async Task Cve_ioc_kind_is_exact_matched_by_search()
    {
        var a = await t.As("analyst");
        await t.Board.PostAsync(a, new PostInput("intel", "vulnerable library", "ioc",
            JsonSerializer.SerializeToElement(new { indicators = new[] { new { kind = "cve", value = "cve-2023-4863", verdict = "malicious" } } })), ct: Ct);
        var hits = await t.Search.RunAsync(new SearchQuery(Q: "CVE-2023-4863"), Ct);
        var hit = Assert.Single(hits.Hits);
        Assert.Equal("CVE-2023-4863", hit.Payload!.Value.GetProperty("indicators")[0].GetProperty("value").GetString());
        Assert.Empty((await t.Search.RunAsync(new SearchQuery(Q: "CVE-2023-486"), Ct)).Hits);
    }

    [DbFact]
    public async Task Publish_needs_a_malicious_ioc_and_dry_run_posts_the_exact_stix()
    {
        var settings = t.Settings with { Ti = AllOn };
        var broker = new Broker(t.Db, t.Audit, t.Board, t.Ms, settings, new Policy(), t.System);
        var agent = await t.As("agent");
        var prm = JsonSerializer.SerializeToElement(new { kind = "domain", value = "bad.example", confidence = 80, description = "Payload host confirmed by the board" });
        var rejected = await broker.RequestAsync(agent, new ActionRequest("publish_ti_indicator", prm, "bad.example served the payload in the incident evidence", TestBoard.IncidentGraphId), Ct);
        Assert.Equal("rejected", rejected.Status);

        await t.Board.PostAsync(agent, new PostInput("incidents", "confirmed", "ioc",
            JsonSerializer.SerializeToElement(new { indicators = new[] { new { kind = "domain", value = "BAD.example", verdict = "malicious" } } }), null, TestBoard.IncidentGraphId), ct: Ct);
        var pending = await broker.RequestAsync(agent, new ActionRequest("publish_ti_indicator", prm, "bad.example served the payload in the incident evidence", TestBoard.IncidentGraphId), Ct);
        Assert.Equal("pending_approval", pending.Status);
        await broker.DecideAsync(await t.As("analyst"), pending.Id, "approve", null, Ct);
        var done = (await broker.GetAsync(pending.Id, Ct))!;
        Assert.Equal("succeeded", done.Status);
        var request = done.Result!.Value.GetProperty("request");
        var indicator = request.GetProperty("body").GetProperty("stixobjects")[1];
        Assert.Equal("[domain-name:value = 'bad.example']", indicator.GetProperty("pattern").GetString());
        var result = (await t.Board.ReadFeedAsync(new FeedQuery(Channel: "containment", Types: ["action_result"], Limit: 200), Ct)).Messages.Last();
        Assert.Contains("Exact request that would be sent", result.Body);
        Assert.Contains("https://api.ti.sentinel.azure.com/workspaces/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview", result.Body);
        Assert.Contains(indicator.GetProperty("id").GetString()!, result.Body);
    }

    private static HttpResponseMessage Fixture(string name) =>
        new(System.Net.HttpStatusCode.OK) { Content = new StringContent(File.ReadAllText(Path.Combine(FixturesDir, name))) };

    private sealed class CountingHandler(Func<HttpResponseMessage> respond, List<string>? urls = null) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            urls?.Add(request.RequestUri!.ToString());
            return Task.FromResult(respond());
        }
    }
}
