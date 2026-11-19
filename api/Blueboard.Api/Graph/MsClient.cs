using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Core;
using Azure.Identity;
using Blueboard.Api.Core;

namespace Blueboard.Api.Graph;

public enum MsApi { Graph, Defender }

/// <summary>
/// Authenticated calls to Microsoft Graph and the Defender for Endpoint API with the Function App's
/// managed identity. Agents never receive these tokens. The token is only ever sent to the exact API
/// origin, and paths with dot-segments are refused so a crafted id can't re-target another endpoint.
/// </summary>
public sealed partial class MsClient(HttpClient http, TokenCredential? credential = null)
{
    public const string GraphOrigin = "https://graph.microsoft.com";
    public const string DefenderOrigin = "https://api.security.microsoft.com";
    private readonly TokenCredential _cred = credential ?? new DefaultAzureCredential();

    private static (string Origin, string Scope) Target(MsApi api) => api switch
    {
        MsApi.Graph => (GraphOrigin, "https://graph.microsoft.com/.default"),
        _ => (DefenderOrigin, "https://api.securitycenter.microsoft.com/.default"),
    };

    [GeneratedRegex(@"(^|/)\.\.?(/|$)")]
    private static partial Regex DotSegment();

    /// <summary>Builds and checks the absolute URL. Public for tests.</summary>
    public static Uri BuildUri(MsApi api, string pathOrUrl)
    {
        var (origin, _) = Target(api);
        var url = pathOrUrl.StartsWith("https://", StringComparison.Ordinal) ? pathOrUrl : origin + pathOrUrl;
        var uri = new Uri(url);
        if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"refusing to send token to {uri.GetLeftPart(UriPartial.Authority)}");
        var rawPath = pathOrUrl.StartsWith("https://", StringComparison.Ordinal) ? uri.AbsolutePath : pathOrUrl.Split('?')[0];
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
        var token = await _cred.GetTokenAsync(new TokenRequestContext([Target(api).Scope]), ct);
        return RolesOf(token.Token);
    }

    internal static string[] RolesOf(string jwt) =>
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(jwt).Claims.Where(c => c.Type == "roles").Select(c => c.Value).Order(StringComparer.Ordinal).ToArray();

    public async Task<JsonElement?> SendAsync(MsApi api, string pathOrUrl, HttpMethod? method = null, object? body = null, CancellationToken ct = default)
    {
        var uri = BuildUri(api, pathOrUrl);
        var token = await _cred.GetTokenAsync(new TokenRequestContext([Target(api).Scope]), ct);
        for (var attempt = 0; ; attempt++)
        {
            using var req = new HttpRequestMessage(method ?? HttpMethod.Get, uri);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
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
                throw new BoardException($"{req.Method} {uri.AbsolutePath}: {(int)res.StatusCode} {msg}", 502);
            }
            return json;
        }
    }
}
