using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Core;
using Azure.Identity;
using Blueboard.Api.Core;

namespace Blueboard.Api.Graph;

public enum MsApi { Graph, Defender, SentinelTi, LogAnalytics, Arm }

/// <summary>
/// Where Microsoft API calls go. Real mode: the exact Microsoft origins, with the managed identity's token.
/// Demo mode (local only: DEMO_MODE and DEV_AUTH, both refused in Azure): a mock API, and no token is ever fetched or sent.
/// </summary>
public sealed record MsOrigins(string Graph, string Defender, bool Mocked, string LogAnalytics = MsClient.LogAnalyticsOrigin, string Arm = MsClient.ArmOrigin)
{
    public static readonly MsOrigins Real = new(MsClient.GraphOrigin, MsClient.DefenderOrigin, false, MsClient.LogAnalyticsOrigin, MsClient.ArmOrigin);

    /// <summary>The base-URL override is honoured only in demo mode; otherwise the real origins, always.</summary>
    public static MsOrigins For(Settings s)
    {
        if (!(s.DemoMode && s.DevAuth)) return Real;
        var graph = Origin(s.GraphBaseUrl, "GRAPH_BASE_URL");
        return new MsOrigins(graph, Origin(s.DefenderBaseUrl, "DEFENDER_BASE_URL"), true, graph, graph);
    }

    private static string Origin(string? url, string name)
    {
        if (url is null || !Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme is not ("http" or "https")
            || u.AbsolutePath != "/" || u.Query.Length > 0 || u.UserInfo.Length > 0)
            throw new InvalidOperationException($"{name} must be an http(s) origin with no path in demo mode");
        return u.GetLeftPart(UriPartial.Authority);
    }
}

/// <summary>
/// Authenticated calls to Microsoft Graph and the Defender for Endpoint API with the Function App's
/// managed identity. Agents never receive these tokens. The token is only ever sent to the exact API
/// origin, and paths with dot-segments are refused so a crafted id can't re-target another endpoint.
/// </summary>
public sealed partial class MsClient(HttpClient http, TokenCredential? credential = null, MsOrigins? origins = null)
{
    public const string GraphOrigin = "https://graph.microsoft.com";
    public const string DefenderOrigin = "https://api.security.microsoft.com";
    /// <summary>Microsoft Sentinel threat intelligence upload API (publish_ti_indicator). Token audience: Azure Resource Manager.</summary>
    public const string SentinelTiOrigin = "https://api.ti.sentinel.azure.com";
    /// <summary>Azure Monitor / Microsoft Sentinel Log Analytics query API (run_sentinel_query).</summary>
    public const string LogAnalyticsOrigin = "https://api.loganalytics.io";
    /// <summary>Azure Resource Manager (Microsoft Sentinel analytics rules, create_detection_rule target sentinel).</summary>
    public const string ArmOrigin = "https://management.azure.com";
    private readonly MsOrigins _origins = origins ?? MsOrigins.Real;
    private readonly Lazy<TokenCredential> _cred = new(() => credential ?? new DefaultAzureCredential());

    public bool Mocked => _origins.Mocked;

    private static string Scope(MsApi api) => api switch
    {
        MsApi.Graph => "https://graph.microsoft.com/.default",
        MsApi.SentinelTi or MsApi.Arm => "https://management.azure.com/.default",
        MsApi.LogAnalytics => "https://api.loganalytics.io/.default",
        _ => "https://api.securitycenter.microsoft.com/.default",
    };

    [GeneratedRegex(@"(^|/)\.\.?(/|$)")]
    private static partial Regex DotSegment();

    /// <summary>Builds and checks the absolute URL against the real Microsoft origins. Public for tests.</summary>
    public static Uri BuildUri(MsApi api, string pathOrUrl) => BuildUri(MsOrigins.Real, api, pathOrUrl);

    /// <summary>Builds and checks the absolute URL: exact origin match, no dot-segments.</summary>
    public static Uri BuildUri(MsOrigins origins, MsApi api, string pathOrUrl)
    {
        // Sentinel TI is never overridden, not even in demo mode: it is a write path and has no mock.
        var origin = api switch
        {
            MsApi.Graph => origins.Graph,
            MsApi.SentinelTi => SentinelTiOrigin,
            MsApi.LogAnalytics => origins.LogAnalytics,
            MsApi.Arm => origins.Arm,
            _ => origins.Defender,
        };
        var absolute = pathOrUrl.StartsWith("https://", StringComparison.Ordinal) || pathOrUrl.StartsWith("http://", StringComparison.Ordinal);
        var uri = new Uri(absolute ? pathOrUrl : origin + pathOrUrl);
        if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"refusing to send token to {uri.GetLeftPart(UriPartial.Authority)}");
        var rawPath = absolute ? uri.AbsolutePath : pathOrUrl.Split('?')[0];
        if (DotSegment().IsMatch(rawPath) || rawPath.Contains("%2e%2e", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("refusing path with dot-segments");
        return uri;
    }

    /// <summary>
    /// Application permissions the managed identity's token for this API carries (its "roles" claim). Lets the setup
    /// checks see which writes would work without calling a write endpoint. The token itself is never returned or logged.
    /// </summary>
    public async Task<string[]> TokenRolesAsync(MsApi api, CancellationToken ct = default)
    {
        if (_origins.Mocked) return []; // demo mode never asks Entra for a token
        var token = await _cred.Value.GetTokenAsync(new TokenRequestContext([Scope(api)]), ct);
        return RolesOf(token.Token);
    }

    internal static string[] RolesOf(string jwt) =>
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(jwt).Claims.Where(c => c.Type == "roles").Select(c => c.Value).Order(StringComparer.Ordinal).ToArray();

    public async Task<JsonElement?> SendAsync(MsApi api, string pathOrUrl, HttpMethod? method = null, object? body = null, CancellationToken ct = default)
    {
        var uri = BuildUri(_origins, api, pathOrUrl);
        // Demo mode never asks Entra for a token: no Microsoft host is contacted and no token can reach the mock.
        var token = _origins.Mocked ? null : (await _cred.Value.GetTokenAsync(new TokenRequestContext([Scope(api)]), ct)).Token;
        for (var attempt = 0; ; attempt++)
        {
            using var req = new HttpRequestMessage(method ?? HttpMethod.Get, uri);
            if (token is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (body is not null) req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var res = await http.SendAsync(req, ct);
            if ((res.StatusCode == HttpStatusCode.TooManyRequests || (int)res.StatusCode >= 500) && attempt < 3)
            {
                var wait = res.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(Math.Pow(2, attempt));
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(wait.TotalSeconds, 30)), ct);
                continue;
            }
            var text = await res.Content.ReadAsStringAsync(ct);
            JsonElement? json = text.Length > 0 && text.TrimStart().StartsWith('{') ? JsonDocument.Parse(text).RootElement.Clone() : null;
            if (!res.IsSuccessStatusCode)
            {
                var msg = json?.TryGetProperty("error", out var e) == true && e.TryGetProperty("message", out var m) ? m.GetString() : res.ReasonPhrase;
                throw new BoardException($"{req.Method} {uri.AbsolutePath}: {(int)res.StatusCode} {msg}", 502) { UpstreamStatus = (int)res.StatusCode };
            }
            return json;
        }
    }
}
