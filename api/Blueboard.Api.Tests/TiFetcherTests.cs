using Blueboard.Contracts;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Blueboard.Api.Core;
using Blueboard.Api.Intel;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>The polite fetcher against a local fake server (no network): TTL, revalidation, redirects, size cap, throttling.</summary>
public class TiFetcherTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly FetchPolicy Feed = new("test", ["feed.example"], TimeSpan.FromHours(1));
    private const string Url = "https://feed.example/data.json";

    /// <summary>A scripted local server: each request is answered by the handler and recorded.</summary>
    private sealed class FakeServer(Func<HttpRequestMessage, int, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public readonly List<HttpRequestMessage> Requests = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(respond(request, Requests.Count));
        }
    }

    private sealed class MemoryCache : IFetchCache
    {
        public readonly ConcurrentDictionary<string, CachedResponse> Rows = new();
        public Task<CachedResponse?> GetAsync(string url, CancellationToken ct) => Task.FromResult(Rows.GetValueOrDefault(url));
        public Task PutAsync(CachedResponse row, CancellationToken ct) { Rows[row.Url] = row; return Task.CompletedTask; }
        public Task TouchAsync(string url, DateTimeOffset at, CancellationToken ct) { Rows[url] = Rows[url] with { FetchedAt = at }; return Task.CompletedTask; }
        public Task DeleteAsync(string url, CancellationToken ct) { Rows.TryRemove(url, out _); return Task.CompletedTask; }
    }

    private static HttpResponseMessage Ok(string body, string? etag = null)
    {
        var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (etag is not null) r.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue(etag);
        return r;
    }

    private static HttpResponseMessage Redirect(string location) =>
        new(HttpStatusCode.Found) { Headers = { Location = new Uri(location, UriKind.RelativeOrAbsolute) } };

    private static (TiFetcher, FakeServer, MemoryCache, Func<DateTimeOffset>, Action<TimeSpan>) Make(Func<HttpRequestMessage, int, HttpResponseMessage> respond, long max = 1000)
    {
        var now = new DateTimeOffset(2026, 11, 19, 0, 0, 0, TimeSpan.Zero);
        var server = new FakeServer(respond);
        var cache = new MemoryCache();
        var f = new TiFetcher(cache, new TiSettings { MaxResponseBytes = max }, server, () => now, (_, _) => Task.CompletedTask);
        return (f, server, cache, () => now, d => now += d);
    }

    [Fact]
    public async Task Second_fetch_inside_the_ttl_makes_no_network_call()
    {
        var (f, server, _, _, _) = Make((_, _) => Ok("{\"a\":1}", "\"v1\""));
        var first = await f.GetAsync(Feed, Url, ct: Ct);
        var second = await f.GetAsync(Feed, Url, ct: Ct);
        Assert.False(first.FromCache);
        Assert.True(second.FromCache);
        Assert.Single(server.Requests);
        Assert.Equal(TiFetcher.UserAgent, server.Requests[0].Headers.UserAgent.ToString());
        Assert.StartsWith("blueboard/", TiFetcher.UserAgent);
        Assert.Contains("(+https://github.com/jusso-dev/blueboard)", TiFetcher.UserAgent);
    }

    [Fact]
    public async Task After_the_ttl_a_304_reuses_the_cache()
    {
        var (f, server, _, _, advance) = Make((req, n) => n == 1 ? Ok("{\"a\":1}", "\"v1\"") : new HttpResponseMessage(HttpStatusCode.NotModified));
        await f.GetAsync(Feed, Url, ct: Ct);
        advance(TimeSpan.FromHours(2));
        var again = await f.GetAsync(Feed, Url, ct: Ct);
        Assert.Equal(2, server.Requests.Count);
        Assert.Equal("\"v1\"", server.Requests[1].Headers.IfNoneMatch.ToString());
        Assert.True(again.FromCache);
        Assert.Equal(304, again.Status);
        Assert.Equal("{\"a\":1}", again.Body);
    }

    [Theory]
    [InlineData("https://evil.example/data.json")]
    [InlineData("http://feed.example/data.json")]
    [InlineData("https://feed.example.evil.example/x")]
    public async Task Redirect_to_another_host_or_to_http_fails_and_is_not_cached(string location)
    {
        var (f, _, cache, _, _) = Make((_, _) => Redirect(location));
        await Assert.ThrowsAsync<TiFetchException>(() => f.GetAsync(Feed, Url, ct: Ct));
        Assert.Empty(cache.Rows);
    }

    [Fact]
    public async Task Same_host_https_redirect_is_followed()
    {
        var (f, server, _, _, _) = Make((req, n) => n == 1 ? Redirect("/moved.json") : Ok("{}"));
        var r = await f.GetAsync(Feed, Url, ct: Ct);
        Assert.Equal("https://feed.example/moved.json", server.Requests[1].RequestUri!.ToString());
        Assert.Equal("{}", r.Body);
    }

    [Fact]
    public async Task Redirect_loops_stop_after_three_hops() =>
        await Assert.ThrowsAsync<TiFetchException>(() => Make((_, n) => Redirect($"/hop{n}")).Item1.GetAsync(Feed, Url, ct: Ct));

    [Fact]
    public async Task Body_over_the_cap_fails_and_is_not_cached()
    {
        var (f, _, cache, _, _) = Make((_, _) => Ok(new string('x', 2000)), max: 1000);
        var ex = await Assert.ThrowsAsync<TiFetchException>(() => f.GetAsync(Feed, Url, ct: Ct));
        Assert.Contains("larger than", ex.Message);
        Assert.Empty(cache.Rows);
    }

    [Fact]
    public async Task Streamed_body_over_the_cap_without_content_length_fails()
    {
        var (f, _, cache, _, _) = Make((_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new MemoryStream(new byte[5000])) }, max: 1000);
        await Assert.ThrowsAsync<TiFetchException>(() => f.GetAsync(Feed, Url, ct: Ct));
        Assert.Empty(cache.Rows);
    }

    [Fact]
    public async Task Throttling_retries_with_retry_after_then_gives_up()
    {
        var waits = new List<TimeSpan>();
        var server = new FakeServer((_, _) =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
            return r;
        });
        var f = new TiFetcher(new MemoryCache(), new TiSettings(), server, null, (d, _) => { waits.Add(d); return Task.CompletedTask; });
        var ex = await Assert.ThrowsAsync<TiFetchException>(() => f.GetAsync(Feed, Url, ct: Ct));
        Assert.Equal(429, ex.Status);
        Assert.Equal(3, server.Requests.Count); // first try + 2 retries, no tight loop
        Assert.All(waits, w => Assert.Equal(TimeSpan.FromSeconds(7), w));
    }

    [Theory]
    [InlineData("http://feed.example/x")]
    [InlineData("https://other.example/x")]
    [InlineData("https://feed.example:8443/x")]
    [InlineData("https://user:pw@feed.example/x")]
    public void Urls_off_the_allowlist_are_refused_before_sending(string url) =>
        Assert.Throws<TiFetchException>(() => TiFetcher.Check(Feed, url));

    [Fact]
    public async Task Fixture_mode_serves_recorded_files_and_never_touches_the_network()
    {
        var server = new FakeServer((_, _) => throw new InvalidOperationException("network used"));
        var f = new TiFetcher(new MemoryCache(), new TiSettings { FixturesDir = Fixtures.Dir }, server);
        var r = await f.GetAsync(Feed, Url, "epss.json", ct: Ct);
        Assert.Contains("CVE-2021-44228", r.Body);
        await Assert.ThrowsAsync<TiFetchException>(() => f.GetAsync(Feed, Url, "../secrets.json", ct: Ct));
    }
}

internal static class Fixtures
{
    public static string Dir => Path.Combine(AppContext.BaseDirectory, "Fixtures", "ti");
    public static string Read(string name) => File.ReadAllText(Path.Combine(Dir, name));
}
