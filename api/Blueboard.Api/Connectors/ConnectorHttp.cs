using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Api.Webhooks;

namespace Blueboard.Api.Connectors;

/// <summary>
/// Calls to one configured connector origin (Okta org, ServiceNow instance, Jira site). The credential header is only
/// ever attached to that exact origin; paths with dot-segments are refused; responses are capped. Outside the local demo
/// the HttpClient uses OutboundGuard's handler: public addresses only, checked at connect time (anti DNS-rebinding),
/// no redirects, no proxy, no cookies.
/// </summary>
public sealed partial class ConnectorHttp(HttpClient http, string origin, string name)
{
    public const int MaxResponseBytes = 2 * 1024 * 1024;

    public string Origin { get; } = origin;
    public string Name { get; } = name;

    [GeneratedRegex(@"(^|/)\.\.?(/|$)")] private static partial Regex DotSegment();

    /// <summary>The production handler: OutboundGuard (public addresses only, no redirects). Demo: no redirects only (the mock is on the compose network).</summary>
    public static HttpClient NewClient(bool mocked) =>
        new(mocked ? new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, UseCookies = false, ConnectTimeout = TimeSpan.FromSeconds(5) } : OutboundGuard.Handler())
        {
            Timeout = TimeSpan.FromSeconds(20),
        };

    /// <summary>origin + path, refusing anything that would leave the origin. Public for tests.</summary>
    public static Uri BuildUri(string origin, string pathAndQuery)
    {
        if (!pathAndQuery.StartsWith('/') || pathAndQuery.StartsWith("//", StringComparison.Ordinal))
            throw new InvalidOperationException("connector path must start with a single /");
        var path = pathAndQuery.Split('?')[0];
        if (DotSegment().IsMatch(path) || path.Contains("%2e", StringComparison.OrdinalIgnoreCase) || path.Contains('\\') || path.Contains('@'))
            throw new InvalidOperationException("refusing connector path with dot-segments or authority characters");
        var uri = new Uri(origin + pathAndQuery);
        if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"refusing to call {uri.GetLeftPart(UriPartial.Authority)}");
        return uri;
    }

    public async Task<(int Status, JsonElement? Json, HttpResponseHeaders Headers)> SendAsync(HttpMethod method, string pathAndQuery,
        AuthenticationHeaderValue? auth, HttpContent? content, CancellationToken ct, bool throwOnError = true)
    {
        var uri = BuildUri(Origin, pathAndQuery);
        for (var attempt = 0; ; attempt++)
        {
            using var req = new HttpRequestMessage(method, uri) { Content = content is null ? null : await CloneAsync(content, ct) };
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            req.Headers.UserAgent.ParseAdd("blueboard-connector/1.0");
            if (auth is not null) req.Headers.Authorization = auth;
            using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            // 429 means the request wasn't processed, so any method may retry; a 5xx may have half-applied a write
            // (a ticket created, then the response lost), so only reads retry on 5xx.
            if ((res.StatusCode == HttpStatusCode.TooManyRequests || ((int)res.StatusCode >= 500 && method == HttpMethod.Get)) && attempt < 2)
            {
                var wait = res.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(1 + attempt * 2);
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(wait.TotalSeconds, 10)), ct);
                continue;
            }
            var text = await ReadCappedAsync(res.Content, ct);
            JsonElement? json = null;
            var trimmed = text.TrimStart();
            if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            {
                try { json = JsonDocument.Parse(text).RootElement.Clone(); }
                catch (JsonException) { json = null; }
            }
            if (!res.IsSuccessStatusCode && throwOnError)
                throw new BoardException($"{Name} {method} {uri.AbsolutePath}: {(int)res.StatusCode} {ErrorText(json) ?? res.ReasonPhrase}", 502) { UpstreamStatus = (int)res.StatusCode };
            return ((int)res.StatusCode, json, res.Headers);
        }
    }

    /// <summary>The vendor's error summary (Okta errorSummary, ServiceNow error.message, Jira errorMessages), never a token.</summary>
    internal static string? ErrorText(JsonElement? json)
    {
        if (json is not { ValueKind: JsonValueKind.Object } j) return null;
        string? s = null;
        if (j.TryGetProperty("errorSummary", out var es) && es.ValueKind == JsonValueKind.String) s = es.GetString();
        else if (j.TryGetProperty("error_description", out var ed) && ed.ValueKind == JsonValueKind.String) s = ed.GetString();
        else if (j.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.Object && e.TryGetProperty("message", out var m)) s = m.GetString();
        else if (j.TryGetProperty("error", out var e2) && e2.ValueKind == JsonValueKind.String) s = e2.GetString();
        else if (j.TryGetProperty("errorMessages", out var em) && em.ValueKind == JsonValueKind.Array && em.GetArrayLength() > 0) s = em[0].GetString();
        return s is null ? null : s.Length > 200 ? s[..200] : s;
    }

    private static async Task<string> ReadCappedAsync(HttpContent content, CancellationToken ct)
    {
        await using var stream = await content.ReadAsStreamAsync(ct);
        using var ms = new MemoryStream();
        var buf = new byte[16_384];
        int n;
        while ((n = await stream.ReadAsync(buf, ct)) > 0)
        {
            if (ms.Length + n > MaxResponseBytes) throw new BoardException("connector response too large", 502);
            ms.Write(buf, 0, n);
        }
        return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }

    /// <summary>HttpContent can be sent once; retries need a fresh copy.</summary>
    private static async Task<HttpContent> CloneAsync(HttpContent c, CancellationToken ct)
    {
        var bytes = await c.ReadAsByteArrayAsync(ct);
        var copy = new ByteArrayContent(bytes);
        foreach (var h in c.Headers) copy.Headers.TryAddWithoutValidation(h.Key, h.Value);
        return copy;
    }

    public static StringContent JsonBody(object body) => new(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
}
