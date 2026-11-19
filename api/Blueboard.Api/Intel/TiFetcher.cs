using System.Net;
using System.Text;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Intel;

public sealed record FetchResult(string Body, bool FromCache, int Status, DateTimeOffset FetchedAt);
public sealed record CachedResponse(string Url, string? ETag, string? LastModified, int Status, string Body, DateTimeOffset FetchedAt);

/// <summary>Where fetched bodies are kept between runs. Postgres in the app, in memory in unit tests.</summary>
public interface IFetchCache
{
    Task<CachedResponse?> GetAsync(string url, CancellationToken ct);
    Task PutAsync(CachedResponse row, CancellationToken ct);
    Task TouchAsync(string url, DateTimeOffset fetchedAt, CancellationToken ct);
    Task DeleteAsync(string url, CancellationToken ct);
}

public sealed class PgFetchCache(Db db) : IFetchCache
{
    public async Task<CachedResponse?> GetAsync(string url, CancellationToken ct)
    {
        await using var cmd = db.Command("select etag, last_modified, status, body, fetched_at from ti_fetch_cache where url = @u").With("u", url);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct)
            ? new CachedResponse(url, r.Get<string>("etag"), r.Get<string>("last_modified"), r.GetInt32(2), r.GetString(3), r.GetFieldValue<DateTimeOffset>(4))
            : null;
    }

    public async Task PutAsync(CachedResponse c, CancellationToken ct)
    {
        await using var cmd = db.Command("""
            insert into ti_fetch_cache (url, etag, last_modified, status, body, fetched_at) values (@u, @e, @l, @s, @b, @f)
            on conflict (url) do update set etag = excluded.etag, last_modified = excluded.last_modified, status = excluded.status,
                                            body = excluded.body, fetched_at = excluded.fetched_at
            """).With("u", c.Url).With("e", c.ETag).With("l", c.LastModified).With("s", c.Status).With("b", c.Body).With("f", c.FetchedAt);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task TouchAsync(string url, DateTimeOffset fetchedAt, CancellationToken ct)
    {
        await using var cmd = db.Command("update ti_fetch_cache set fetched_at = @f where url = @u").With("f", fetchedAt).With("u", url);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task DeleteAsync(string url, CancellationToken ct)
    {
        await using var cmd = db.Command("delete from ti_fetch_cache where url = @u").With("u", url);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

/// <summary>What one source may fetch: an exact https host allowlist and a minimum cache lifetime.</summary>
public sealed record FetchPolicy(string SourceId, string[] Hosts, TimeSpan MinTtl);

/// <summary>
/// The one polite, cached GET every outside threat intel source uses (ported from Crosswire's politeFetch):
///  - identifiable User-Agent with a link to the repo;
///  - no network call while the cached copy is younger than the source's TTL; If-None-Match / If-Modified-Since
///    when revalidating, and a 304 reuses the cache;
///  - https only, exact per-source host allowlist, redirects followed only to https on the same host (3 hops max);
///  - 30 s timeout; at most 2 retries on 429/503, honouring Retry-After (capped at 60 s);
///  - bodies over the size cap are refused (Content-Length and streamed count) and never cached.
/// No Microsoft token ever goes through here: Microsoft APIs use MsClient.
/// In local demo mode (TI_FIXTURES_DIR) recorded fixtures are served instead of the network.
/// </summary>
public sealed class TiFetcher
{
    public const string Version = "2.0.0";
    public const string UserAgent = $"blueboard/{Version} (+https://github.com/jusso-dev/blueboard)";
    public const int MaxRedirects = 3;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private readonly IFetchCache _cache;
    private readonly long _maxBytes;
    private readonly string? _fixtures;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<TimeSpan, CancellationToken, Task> _sleep;

    public TiFetcher(IFetchCache cache, TiSettings settings, HttpMessageHandler? handler = null,
        Func<DateTimeOffset>? now = null, Func<TimeSpan, CancellationToken, Task>? sleep = null)
    {
        _http = new HttpClient(handler ?? new SocketsHttpHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.All }, disposeHandler: handler is null)
        {
            Timeout = System.Threading.Timeout.InfiniteTimeSpan, // per request, below
        };
        _cache = cache;
        _maxBytes = settings.MaxResponseBytes;
        _fixtures = settings.FixturesDir;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _sleep = sleep ?? Task.Delay;
    }

    public bool FixtureMode => _fixtures is not null;

    /// <summary>Checks a URL against the policy before anything is sent. Public for tests.</summary>
    public static Uri Check(FetchPolicy policy, string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps)
            throw new TiFetchException($"{policy.SourceId}: refusing non-https URL");
        if (!u.IsDefaultPort || !policy.Hosts.Contains(u.Host, StringComparer.OrdinalIgnoreCase))
            throw new TiFetchException($"{policy.SourceId}: host {u.Host} is not on this source's allowlist");
        if (u.UserInfo.Length > 0) throw new TiFetchException($"{policy.SourceId}: refusing URL with credentials");
        return u;
    }

    public async Task<FetchResult> GetAsync(FetchPolicy policy, string url, string? fixture = null,
        IReadOnlyDictionary<string, string>? headers = null, CancellationToken ct = default)
    {
        var uri = Check(policy, url);
        if (_fixtures is not null) return await FixtureAsync(policy, fixture, ct);

        var ttl = policy.MinTtl < TimeSpan.FromMinutes(1) ? TimeSpan.FromMinutes(1) : policy.MinTtl;
        var cached = await _cache.GetAsync(url, ct);
        if (cached is not null && _now() - cached.FetchedAt < ttl)
        {
            await RefuseOversized(cached, ct);
            return new FetchResult(cached.Body, true, cached.Status, cached.FetchedAt);
        }

        for (var attempt = 0; ; attempt++)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);
            using var res = await SendSameHostAsync(policy, uri, cached, headers, timeout.Token);
            if (res.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable && attempt < 2)
            {
                var wait = res.Headers.RetryAfter?.Delta
                           ?? (res.Headers.RetryAfter?.Date is { } at ? at - _now() : TimeSpan.FromSeconds(2 * Math.Pow(2, attempt)));
                await _sleep(wait < TimeSpan.Zero ? TimeSpan.Zero : wait > TimeSpan.FromSeconds(60) ? TimeSpan.FromSeconds(60) : wait, ct);
                continue;
            }
            var fetchedAt = _now();
            if (res.StatusCode == HttpStatusCode.NotModified && cached is not null)
            {
                await RefuseOversized(cached, ct);
                await _cache.TouchAsync(url, fetchedAt, ct);
                return new FetchResult(cached.Body, true, 304, fetchedAt);
            }
            if (!res.IsSuccessStatusCode) throw new TiFetchException($"{policy.SourceId}: {uri.Host}{uri.AbsolutePath} returned HTTP {(int)res.StatusCode}", (int)res.StatusCode);
            var body = await ReadCappedAsync(res, timeout.Token);
            await _cache.PutAsync(new CachedResponse(url, res.Headers.ETag?.ToString(), res.Content.Headers.LastModified?.ToString("R"),
                (int)res.StatusCode, body, fetchedAt), ct);
            return new FetchResult(body, false, (int)res.StatusCode, fetchedAt);
        }
    }

    /// <summary>A status-only HEAD (the cve.watch re-check). Same host and https rules; nothing is cached or read.</summary>
    public async Task<int> HeadAsync(FetchPolicy policy, string url, TimeSpan timeout, CancellationToken ct = default)
    {
        var uri = Check(policy, url);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        using var req = new HttpRequestMessage(HttpMethod.Head, uri);
        req.Headers.UserAgent.ParseAdd(UserAgent);
        using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token);
        return (int)res.StatusCode;
    }

    private async Task<HttpResponseMessage> SendSameHostAsync(FetchPolicy policy, Uri uri, CachedResponse? cached,
        IReadOnlyDictionary<string, string>? headers, CancellationToken ct)
    {
        var current = uri;
        for (var hop = 0; ; hop++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, current);
            req.Headers.UserAgent.ParseAdd(UserAgent);
            req.Headers.Accept.ParseAdd("application/json");
            if (cached?.ETag is { } etag) req.Headers.TryAddWithoutValidation("If-None-Match", etag);
            if (cached?.LastModified is { } lm) req.Headers.TryAddWithoutValidation("If-Modified-Since", lm);
            foreach (var (k, v) in headers ?? new Dictionary<string, string>()) req.Headers.TryAddWithoutValidation(k, v);
            var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            var code = (int)res.StatusCode;
            if (code is < 300 or > 399 || code == 304) return res;
            var location = res.Headers.Location;
            res.Dispose();
            if (location is null) throw new TiFetchException($"{policy.SourceId}: {uri.Host} sent a redirect without a location");
            var next = location.IsAbsoluteUri ? location : new Uri(current, location);
            if (next.Scheme != Uri.UriSchemeHttps || !string.Equals(next.Host, uri.Host, StringComparison.OrdinalIgnoreCase) || !next.IsDefaultPort)
                throw new TiFetchException($"{policy.SourceId}: {uri.Host} redirected to another host or to plain http");
            if (hop >= MaxRedirects - 1) throw new TiFetchException($"{policy.SourceId}: more than {MaxRedirects} redirects from {uri.Host}");
            current = next;
        }
    }

    private async Task<string> ReadCappedAsync(HttpResponseMessage res, CancellationToken ct)
    {
        if (res.Content.Headers.ContentLength is { } declared && declared > _maxBytes) throw TooLarge();
        await using var stream = await res.Content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int n;
        while ((n = await stream.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + n > _maxBytes) throw TooLarge();
            buffer.Write(chunk, 0, n);
        }
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    private async Task RefuseOversized(CachedResponse cached, CancellationToken ct)
    {
        if (Encoding.UTF8.GetByteCount(cached.Body) <= _maxBytes) return;
        await _cache.DeleteAsync(cached.Url, ct);
        throw TooLarge();
    }

    private TiFetchException TooLarge() => new($"response larger than {_maxBytes} bytes refused");

    private async Task<FetchResult> FixtureAsync(FetchPolicy policy, string? fixture, CancellationToken ct)
    {
        if (fixture is null || fixture.Contains("..") || Path.IsPathRooted(fixture))
            throw new TiFetchException($"{policy.SourceId}: no recorded fixture for this request");
        var path = Path.Combine(_fixtures!, fixture);
        if (!File.Exists(path)) throw new TiFetchException($"{policy.SourceId}: fixture {fixture} not found", 404);
        return new FetchResult(await File.ReadAllTextAsync(path, ct), true, 200, File.GetLastWriteTimeUtc(path));
    }
}

public sealed class TiFetchException(string message, int? status = null) : Exception(message)
{
    public int? Status { get; } = status;
}
