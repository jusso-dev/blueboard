using Blueboard.Contracts;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Issue #1: the Microsoft base-URL override exists only for the local demo and is refused everywhere else.</summary>
public class DemoModeTests
{
    private static Settings From(params (string Key, string Value)[] vars)
    {
        var d = vars.ToDictionary(v => v.Key, v => v.Value);
        return Settings.FromEnvironment(k => d.GetValueOrDefault(k));
    }

    private static readonly (string, string)[] Mock = [("GRAPH_BASE_URL", "http://mock-msapi:8080"), ("DEFENDER_BASE_URL", "http://mock-msapi:8080")];

    [Fact]
    public void Override_without_demo_mode_is_refused_at_startup()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => From([.. Mock, ("DEV_AUTH", "true")]));
        Assert.Contains("DEMO_MODE", ex.Message);
    }

    [Fact]
    public void Demo_mode_needs_dev_auth() =>
        Assert.Throws<InvalidOperationException>(() => From([.. Mock, ("DEMO_MODE", "true")]));

    [Fact]
    public void Demo_mode_is_refused_in_azure() =>
        Assert.Throws<InvalidOperationException>(() => From([.. Mock, ("DEMO_MODE", "true"), ("DEV_AUTH", "true"), ("WEBSITE_INSTANCE_ID", "abc")]));

    [Fact]
    public void Real_mode_ignores_base_urls_and_keeps_exact_origins()
    {
        // Settings built in code (tests, tools) can carry URLs without DEMO_MODE: MsOrigins still returns the real hosts.
        var s = new Settings { DevAuth = true, GraphBaseUrl = "https://evil.example", DefenderBaseUrl = "https://evil.example" };
        var o = MsOrigins.For(s);
        Assert.False(o.Mocked);
        Assert.Equal(MsClient.GraphOrigin, o.Graph);
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(o, MsApi.Graph, "https://evil.example/v1.0/me"));
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(o, MsApi.Defender, "http://mock-msapi:8080/api/machines"));
    }

    [Fact]
    public void Demo_mode_without_dev_auth_never_mocks() =>
        Assert.False(MsOrigins.For(new Settings { DemoMode = true, DevAuth = false, GraphBaseUrl = "http://m:1", DefenderBaseUrl = "http://m:1" }).Mocked);

    [Fact]
    public void Demo_mode_targets_only_the_mock_origin()
    {
        var o = MsOrigins.For(From([.. Mock, ("DEMO_MODE", "true"), ("DEV_AUTH", "true")]));
        Assert.True(o.Mocked);
        Assert.Equal("mock-msapi", MsClient.BuildUri(o, MsApi.Graph, "/v1.0/security/incidents").Host);
        // In demo mode the real Microsoft hosts are refused too: nothing leaves for Microsoft.
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(o, MsApi.Graph, "https://graph.microsoft.com/v1.0/me"));
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(o, MsApi.Graph, "/v1.0/users/../me"));
    }

    [Theory]
    [InlineData("http://mock:8080/v1.0")]
    [InlineData("ftp://mock")]
    [InlineData("http://user:pw@mock:8080")]
    public void Demo_base_url_must_be_a_bare_origin(string url) =>
        Assert.Throws<InvalidOperationException>(() => MsOrigins.For(new Settings { DemoMode = true, DevAuth = true, GraphBaseUrl = url, DefenderBaseUrl = "http://m:1" }));

    [Fact]
    public async Task Demo_client_sends_no_token()
    {
        var handler = new Capture();
        var o = new MsOrigins("http://mock:8080", "http://mock:8080", true);
        var ms = new MsClient(new HttpClient(handler), new ThrowingCredential(), o);
        await ms.SendAsync(MsApi.Graph, "/v1.0/security/incidents", ct: TestContext.Current.CancellationToken);
        Assert.Null(handler.Last!.Headers.Authorization);
        Assert.Equal("mock", handler.Last.RequestUri!.Host);
    }

    private sealed class Capture : HttpMessageHandler
    {
        public HttpRequestMessage? Last;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Last = request;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("{\"value\":[]}") });
        }
    }

    private sealed class ThrowingCredential : Azure.Core.TokenCredential
    {
        public override Azure.Core.AccessToken GetToken(Azure.Core.TokenRequestContext c, CancellationToken ct) => throw new InvalidOperationException("no token in demo mode");
        public override ValueTask<Azure.Core.AccessToken> GetTokenAsync(Azure.Core.TokenRequestContext c, CancellationToken ct) => throw new InvalidOperationException("no token in demo mode");
    }
}
