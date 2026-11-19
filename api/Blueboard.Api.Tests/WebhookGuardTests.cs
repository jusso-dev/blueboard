using System.Net;
using Blueboard.Api.Core;
using Blueboard.Api.Webhooks;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Issue #23: webhook URLs can't be used to reach internal addresses, and signatures verify.</summary>
public class WebhookGuardTests
{
    private static readonly string[] Allowed = ["hooks.contoso.com"];

    [Theory]
    [InlineData("http://hooks.contoso.com/x", "https")]
    [InlineData("https://other.example/x", "allowlist")]
    [InlineData("https://user:pw@hooks.contoso.com/x", "credentials")]
    [InlineData("https://203.0.113.9/x", "IP address")]
    [InlineData("https://[::1]/x", "IP address")]
    [InlineData("https://hooks.contoso.com:22/x", "port")]
    [InlineData("https://hooks.contoso.com.evil.example/x", "allowlist")]
    public void Bad_urls_are_refused(string url, string why)
    {
        var ex = Assert.Throws<BoardException>(() => OutboundGuard.CheckUrl(url, Allowed));
        Assert.Contains(why, ex.Message);
    }

    [Fact]
    public void Allowlisted_https_host_is_accepted() =>
        Assert.Equal("hooks.contoso.com", OutboundGuard.CheckUrl("https://HOOKS.contoso.com/agent/wake", Allowed));

    [Fact]
    public void No_allowlist_means_no_webhooks() =>
        Assert.Equal(403, Assert.Throws<BoardException>(() => OutboundGuard.CheckUrl("https://hooks.contoso.com/x", [])).Status);

    [Theory]
    [InlineData("127.0.0.1")] [InlineData("10.1.2.3")] [InlineData("172.16.0.1")] [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")] [InlineData("100.64.0.1")] [InlineData("0.0.0.0")] [InlineData("224.0.0.1")]
    [InlineData("::1")] [InlineData("fe80::1")] [InlineData("fd00::1")] [InlineData("::ffff:10.0.0.1")] [InlineData("64:ff9b::a00:1")]
    public void Private_and_special_addresses_are_not_public(string ip) => Assert.False(OutboundGuard.IsPublic(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("20.53.1.1")] [InlineData("1.1.1.1")] [InlineData("2606:4700:4700::1111")]
    public void Public_addresses_are_public(string ip) => Assert.True(OutboundGuard.IsPublic(IPAddress.Parse(ip)));

    [Fact]
    public async Task Rebinding_to_loopback_is_refused_at_resolve_time()
    {
        // localhost resolves to loopback: the connect step refuses it even if the name were on the allowlist.
        var ex = await Assert.ThrowsAsync<BoardException>(() => OutboundGuard.ResolvePublicAsync("localhost", TestContext.Current.CancellationToken));
        Assert.Contains("non-public", ex.Message);
    }

    [Fact]
    public void Signature_round_trips_and_rejects_tampering_and_replay()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var ts = now.ToUnixTimeSeconds();
        const string body = """{"event":"mention","message_id":"x"}""";
        var sig = WebhookSignature.Sign("whsec_test", ts, body);
        Assert.StartsWith("sha256=", sig);
        Assert.True(WebhookSignature.Verify("whsec_test", ts.ToString(), body, sig, now));
        Assert.False(WebhookSignature.Verify("whsec_test", ts.ToString(), body + " ", sig, now));
        Assert.False(WebhookSignature.Verify("whsec_other", ts.ToString(), body, sig, now));
        Assert.False(WebhookSignature.Verify("whsec_test", ts.ToString(), body, sig, now.AddMinutes(6)));
    }

    [Fact]
    public void Backoff_grows_and_is_capped()
    {
        Assert.Equal(TimeSpan.FromSeconds(10), WebhookService.Backoff(1));
        Assert.True(WebhookService.Backoff(5) > WebhookService.Backoff(4));
        Assert.Equal(TimeSpan.FromMinutes(30), WebhookService.Backoff(30));
    }

    [Fact]
    public void Signing_key_must_be_strong()
    {
        Assert.Throws<InvalidOperationException>(() => Settings.FromEnvironment(k => k == "WEBHOOK_SIGNING_KEY" ? "c2hvcnQ=" : null));
        var ok = Settings.FromEnvironment(k => k == "WEBHOOK_SIGNING_KEY" ? Convert.ToBase64String(new byte[32]) : k == "WEBHOOK_ALLOWED_HOSTS" ? "A.example, b.example" : null);
        Assert.Equal(["a.example", "b.example"], ok.WebhookAllowedHosts);
    }
}
