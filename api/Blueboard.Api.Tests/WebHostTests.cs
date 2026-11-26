using Blueboard.Web;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Issue #1: the web host serves a dev-auth config only for the local demo, never in Azure.</summary>
public class WebHostTests
{
    private static WebConfig From(params (string Key, string Value)[] vars)
    {
        var d = vars.ToDictionary(v => v.Key, v => v.Value);
        return WebConfig.FromEnvironment(false, k => d.GetValueOrDefault(k));
    }

    [Fact]
    public void Dev_mode_reports_dev_and_drops_entra_and_hsts()
    {
        var c = From(("BLUEBOARD_DEV_AUTH", "true"), ("BLUEBOARD_API_URL", "http://localhost:7370"));
        Assert.Equal("dev", c.Public.Mode);
        Assert.Equal("http://localhost:7370/api", c.Public.ApiBaseUrl);
        Assert.Null(c.Public.ClientId);
        var headers = SecurityHeaders.For(c).ForPath("/").ToDictionary(h => h.Key, h => h.Value);
        Assert.False(headers.ContainsKey("Strict-Transport-Security"));
        Assert.Contains("connect-src 'self' http://localhost:7370;", headers["Content-Security-Policy"]);
        Assert.DoesNotContain("login", headers["Content-Security-Policy"]);
    }

    [Fact]
    public void Dev_mode_is_refused_in_azure() =>
        Assert.Throws<InvalidOperationException>(() => From(("BLUEBOARD_DEV_AUTH", "true"), ("WEBSITE_INSTANCE_ID", "x")));

    [Fact]
    public void Default_is_entra_with_hsts()
    {
        var c = From(("BLUEBOARD_API_URL", "https://api.example"), ("BLUEBOARD_TENANT_ID", Guid.NewGuid().ToString()),
            ("BLUEBOARD_CLIENT_ID", "c"), ("BLUEBOARD_API_SCOPE", "api://x/Board.Access"));
        Assert.Equal("entra", c.Public.Mode);
        Assert.Equal("https://api.example/api", c.Public.ApiBaseUrl);
        Assert.Contains(SecurityHeaders.For(c).ForPath("/"), h => h.Key == "Strict-Transport-Security");
        var csp = SecurityHeaders.For(c).ForPath("/").Single(h => h.Key == "Content-Security-Policy").Value;
        Assert.True(c.GifsEnabled);
        Assert.Contains("img-src 'self' data: https://media.giphy.com", csp);
    }

    [Fact]
    public void Disabling_gifs_locks_img_src_to_self_and_data()
    {
        var c = From(("BLUEBOARD_DEV_AUTH", "true"), ("BLUEBOARD_GIFS_ENABLED", "false"));
        Assert.False(c.GifsEnabled);
        Assert.False(c.Public.GifsEnabled);
        var csp = SecurityHeaders.For(c).ForPath("/").Single(h => h.Key == "Content-Security-Policy").Value;
        Assert.Contains("img-src 'self' data:;", csp);
        Assert.DoesNotContain("giphy", csp);
    }
}
