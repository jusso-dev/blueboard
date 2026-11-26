using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Blueboard.Api.Intel;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Regression tests for adversarial hardening, private IP TI blocking, tech stack watches, and GIF validation.</summary>
public class HardeningAndFeaturesTests
{
    // ── Private IP blocking in Threat Intel ────────────────────────────────────────────────────

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("10.20.1.42")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.1.1")]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.254")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456:789a::1")]
    [InlineData("::ffff:10.0.0.5")]
    [InlineData("::ffff:192.168.1.1")]
    [InlineData("2002:0a00:0001::1")]
    public void Private_and_non_routable_ips_are_detected(string ip) =>
        Assert.True(Indicators.IsPrivateIp(ip));

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("172.32.0.1")]
    [InlineData("100.128.0.1")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("203.0.113.5")]
    [InlineData("198.51.100.23")]
    [InlineData("2001:db8::1")]
    public void Public_and_fixture_doc_ips_are_not_marked_private(string ip) =>
        Assert.False(Indicators.IsPrivateIp(ip));

    [Fact]
    public void Sentinel_kql_builder_refuses_private_ips_and_private_ip_urls()
    {
        Assert.Throws<BoardException>(() => Kql.SentinelIndicators([new("ip", "10.20.1.42")]));
        Assert.Throws<BoardException>(() => Kql.SentinelIndicators([new("ip", "192.168.1.5")]));
        Assert.Throws<BoardException>(() => Kql.SentinelIndicators([new("ip", "::ffff:10.0.0.1")]));
        Assert.Throws<BoardException>(() => Kql.SentinelIndicators([new("url", "https://10.0.0.1/admin")]));
        var kql = Kql.SentinelIndicators([new("ip", "1.1.1.1"), new("domain", "evil.example")]);
        Assert.Contains("1.1.1.1", kql);
        Assert.Contains("evil.example", kql);
    }

    [Fact]
    public void Auto_enrichment_indicator_extraction_drops_private_ips()
    {
        var entities = new IncidentEntities(
            [], [],
            ["10.20.1.42", "192.168.1.5", "127.0.0.1", "fe80::1", "1.1.1.1"],
            ["https://10.0.0.1/admin", "https://evil.example/c2"],
            [],
            [new FileRef("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", null, "payload.exe")],
            [], []);
        var keys = IntelService.IndicatorsOf(entities);
        Assert.Contains(new IntelKey("ip", "1.1.1.1"), keys);
        Assert.Contains(new IntelKey("url", "https://evil.example/c2"), keys);
        Assert.DoesNotContain(keys, k => k.Value is "10.20.1.42" or "192.168.1.5" or "127.0.0.1" or "fe80::1" or "https://10.0.0.1/admin");
        Assert.Contains(keys, k => k.Kind == "sha256");
    }

    // ── Adversarial security regressions ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("DeviceInfo | take 1; .show tables")]
    [InlineData("DeviceInfo | take 1;\n.drop table Foo")]
    [InlineData("DeviceInfo | evaluate python(typeof(*), 'import os')")]
    [InlineData("DeviceInfo | evaluate r(typeof(*), 'system(\"id\")')")]
    public void Kql_validator_blocks_chained_management_commands_and_script_plugins(string kql) =>
        Assert.Throws<BoardException>(() => Enrichment.ValidateKql(kql, "P1D"));

    [Fact]
    public void Protected_indicators_canonicalise_ipv4_mapped_and_uncompressed_ipv6()
    {
        var protectedSet = new HashSet<string> { "10.0.0.1", "2001:db8::1" };
        Assert.True(PolicyEngine.MatchesProtectedIndicator("::ffff:10.0.0.1", protectedSet));
        Assert.True(PolicyEngine.MatchesProtectedIndicator("2001:0db8:0000:0000:0000:0000:0000:0001", protectedSet));
        Assert.True(PolicyEngine.MatchesProtectedIndicator("https://[2001:0db8::1]/login", protectedSet));
        Assert.False(PolicyEngine.MatchesProtectedIndicator("1.1.1.1", protectedSet));
    }

    [Theory]
    [InlineData("https://example.com/a)(b")]
    [InlineData("https://example.com/<script>")]
    [InlineData("javascript:alert(1)")]
    public void SafeUrl_blocks_markdown_breakout_and_unsafe_schemes(string url) =>
        Assert.Null(J.SafeUrl(url));

    [Theory]
    [InlineData("../etc/passwd")]
    [InlineData("foo/bar")]
    [InlineData("foo?bar=1")]
    [InlineData("a..b")]
    public void Pwnwatch_slug_validation_blocks_traversal(string slug) =>
        Assert.False(PwnWatchParser.IsValidSlug(slug));

    [Theory]
    [InlineData("AKIAIOSFODNN7EXAMPLE1234")]
    [InlineData("sk-proj-abcdefghijklmnopqrstuvwxyz123456")]
    [InlineData("xoxb-123456789012-123456789012-abcdef")]
    [InlineData("DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF==")]
    public void Secret_leak_detector_catches_expanded_token_formats(string text) =>
        Assert.NotNull(BoardService.DetectSecretLeak(text));

    // ── Tech stack & watchlists ────────────────────────────────────────────────────────────────

    [Fact]
    public void Watches_match_stack_and_vendor_kinds()
    {
        var watchable = new Watchable(
            "Critical auth bypass in FortiOS",
            "Affects Fortinet FortiOS appliances in edge deployments",
            ["edge"],
            ["CVE-2026-9999"],
            ["fortios"]);
        var watches = new[]
        {
            new Watch(Guid.NewGuid(), "stack", "fortios", true, "manual", "Edge", null),
            new Watch(Guid.NewGuid(), "vendor", "fortinet", true, "manual", null, null),
            new Watch(Guid.NewGuid(), "stack", "kubernetes", true, "manual", null, null),
        };
        var matched = Watches.Matching(watches, watchable);
        Assert.Contains("stack:fortios", matched);
        Assert.Contains("vendor:fortinet", matched);
        Assert.DoesNotContain("stack:kubernetes", matched);
    }

    // ── Slack-like GIF validation & curated search ─────────────────────────────────────────────

    [Theory]
    [InlineData("https://media.giphy.com/media/QMHoU66sBXqqLqYvGO/giphy.gif")]
    [InlineData("https://media2.giphy.com/media/3o7abKhOpu0NwenH3O/200w.gif")]
    [InlineData("https://i.giphy.com/media/abc/giphy.gif")]
    [InlineData("https://media.tenor.com/xyz/tenor.gif")]
    public void Allowed_gif_urls_pass(string url) => Assert.True(Gifs.IsAllowedUrl(url));

    [Theory]
    [InlineData("http://media.giphy.com/media/abc/giphy.gif")]
    [InlineData("https://evil.example/tracker.gif")]
    [InlineData("https://media.giphy.com.evil.example/giphy.gif")]
    [InlineData("https://user@media.giphy.com/media/abc/giphy.gif")]
    [InlineData("https://media.giphy.com:8443/media/abc/giphy.gif")]
    [InlineData("https://media.giphy.com/media/abc/giphy.gif#frag")]
    [InlineData("https://media.giphy.com/media/abc/giphy.gif)")]
    public void Disallowed_gif_urls_are_rejected(string url) => Assert.False(Gifs.IsAllowedUrl(url));

    [Fact]
    public void Payloads_validate_gif_attachments_strictly()
    {
        var ok = Payloads.Validate("chat", JsonDocument.Parse("""
            {"gif":{"url":"https://media.giphy.com/media/QMHoU66sBXqqLqYvGO/giphy.gif","title":"This is fine","width":480,"height":270}}
            """).RootElement);
        Assert.Equal("giphy", ok.GetProperty("gif").GetProperty("provider").GetString());

        Assert.Throws<BoardException>(() => Payloads.Validate("chat", JsonDocument.Parse("""
            {"gif":{"url":"https://attacker.example/pixel.gif","title":"bad"}}
            """).RootElement));
    }

    [Fact]
    public void Curated_gifs_all_use_allowlisted_urls_and_match_queries()
    {
        Assert.NotEmpty(Gifs.Curated);
        Assert.All(Gifs.Curated, g =>
        {
            Assert.True(Gifs.IsAllowedUrl(g.Url), g.Url);
            Assert.True(Gifs.IsAllowedUrl(g.PreviewUrl), g.PreviewUrl);
        });
        var fine = Gifs.SearchCurated("this is fine", 5);
        Assert.Equal("This is fine", fine[0].Title);
    }

    private static DateTimeOffset Now() => new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);
}
