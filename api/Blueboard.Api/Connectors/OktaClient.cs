using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;

namespace Blueboard.Api.Connectors;

/// <summary>
/// Okta Management API (v1) as an OAuth 2.0 service app. Preferred: client credentials with private_key_jwt, the client
/// assertion signed by Key Vault (non-exportable key), scoped to OktaSettings.DefaultScopes; tokens are cached until a
/// minute before they expire. Fallback (less preferred, documented): an SSWS API token read from Key Vault. Every call
/// goes to the one configured org origin through ConnectorHttp (OutboundGuard). Agents never see either credential.
/// </summary>
public sealed partial class OktaClient
{
    private readonly OktaSettings _s;
    private readonly ConnectorHttp _http;
    private readonly IJwtSigner? _signer;
    private readonly bool _mocked;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private (string Token, DateTimeOffset Expires)? _token;

    public OktaClient(OktaSettings s, HttpClient http, IJwtSigner? signer, bool mocked)
    {
        _s = s;
        _http = new ConnectorHttp(http, s.OrgUrl ?? throw new InvalidOperationException("Okta is not configured"), "Okta");
        _signer = signer;
        _mocked = mocked;
    }

    [GeneratedRegex("^00[A-Za-z0-9]{15,20}$")] public static partial Regex OktaId();
    /// <summary>A login / email: no whitespace, path, query, quote or escape characters (it goes into URL paths and SCIM filters).</summary>
    [GeneratedRegex(@"^[^\s/\\?#@""'%]{1,200}@[^\s/\\?#@""'%]{1,200}\.[^\s/\\?#@""'%]{1,60}$")] public static partial Regex Login();

    /// <summary>An Okta user id (00u…) or a login/email: the only shapes a user reference may take (no path characters).</summary>
    public static bool IsUserRef(string s) => s.Length <= 320 && (OktaId().IsMatch(s) || Login().IsMatch(s));

    private async Task<AuthenticationHeaderValue?> AuthAsync(CancellationToken ct)
    {
        if (_mocked) return null; // the demo mock gets no credential
        if (_s.AuthMode == "ssws") return new AuthenticationHeaderValue("SSWS", _s.ApiToken);
        if (_token is { } t && t.Expires > DateTimeOffset.UtcNow.AddMinutes(1)) return new AuthenticationHeaderValue("Bearer", t.Token);
        await _gate.WaitAsync(ct);
        try
        {
            if (_token is { } t2 && t2.Expires > DateTimeOffset.UtcNow.AddMinutes(1)) return new AuthenticationHeaderValue("Bearer", t2.Token);
            var endpoint = $"{_s.OrgUrl}/oauth2/v1/token";
            var signer = _signer ?? throw new InvalidOperationException("no Okta signer");
            // A fresh client assertion (new jti) for every attempt: a 429 retry must not replay the one Okta already saw.
            async Task<HttpContent> Form(int _) => new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["scope"] = _s.Scopes,
                ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ["client_assertion"] = await ClientAssertion.CreateAsync(signer, _s.ClientId!, endpoint, _s.JwkKid, DateTimeOffset.UtcNow, ct),
            });
            var (_, json, _) = await _http.SendFreshAsync(HttpMethod.Post, "/oauth2/v1/token", null, Form, ct);
            var access = json?.TryGetProperty("access_token", out var a) == true ? a.GetString() : null;
            if (access is null) throw new BoardException("Okta token response had no access_token", 502);
            var secs = json!.Value.TryGetProperty("expires_in", out var e) && e.TryGetInt32(out var n) ? n : 3600;
            _token = (access, DateTimeOffset.UtcNow.AddSeconds(secs));
            return new AuthenticationHeaderValue("Bearer", access);
        }
        finally { _gate.Release(); }
    }

    private async Task<JsonElement?> GetAsync(string path, CancellationToken ct) => (await _http.SendAsync(HttpMethod.Get, path, await AuthAsync(ct), null, ct)).Json;

    /// <summary>GET that returns null on 403/404 instead of throwing (a missing optional scope such as okta.roles.read).</summary>
    private async Task<(JsonElement? Json, int Status)> TryGetAsync(string path, CancellationToken ct)
    {
        var (status, json, _) = await _http.SendAsync(HttpMethod.Get, path, await AuthAsync(ct), null, ct, throwOnError: false);
        if (status is 401 or 403 or 404) return (null, status);
        if (status >= 400) throw new BoardException($"Okta GET {path.Split('?')[0]}: {status} {ConnectorHttp.ErrorText(json)}", 502) { UpstreamStatus = status };
        return (json, status);
    }

    public async Task PostAsync(string path, CancellationToken ct) => await _http.SendAsync(HttpMethod.Post, path, await AuthAsync(ct), null, ct);
    public async Task DeleteAsync(string path, CancellationToken ct) => await _http.SendAsync(HttpMethod.Delete, path, await AuthAsync(ct), null, ct);

    /// <summary>The user by id or login (Okta resolves both on /api/v1/users/{id}); null when not found.</summary>
    public async Task<JsonElement?> FindUserAsync(string userRef, CancellationToken ct)
    {
        if (!IsUserRef(userRef)) throw new BoardException("user must be an Okta user id (00u…) or a login / email");
        var (json, status) = await TryGetAsync($"/api/v1/users/{Uri.EscapeDataString(userRef)}", ct);
        if (status is 401 or 403) throw new BoardException($"Okta refused the user read ({status}): check the credential and the okta.users.read scope", 502) { UpstreamStatus = status };
        if (json is not null || OktaId().IsMatch(userRef)) return json;
        // A login that differs from the email: search the profile (exact match on email).
        var (list, _) = await TryGetAsync($"/api/v1/users?search={Uri.EscapeDataString($"profile.email eq \"{userRef}\"")}&limit=2", ct);
        return list is { ValueKind: JsonValueKind.Array } arr && arr.GetArrayLength() == 1 ? arr[0].Clone() : null;
    }

    public sealed record UserContext(
        string Id, string? Login, string? Email, string? SecondEmail, string? DisplayName, string? Status, string? LastLogin,
        string? PasswordChanged, IReadOnlyList<object> Factors, IReadOnlyList<string> Groups, IReadOnlyList<string>? AdminRoles, bool AdminRolesChecked);

    /// <summary>Status, factors enrolled, last login, groups (up to 50) and admin roles (needs okta.roles.read; otherwise not checked).</summary>
    public async Task<UserContext?> UserContextAsync(string userRef, CancellationToken ct)
    {
        if (await FindUserAsync(userRef, ct) is not { } u) return null;
        var id = Str(u, "id")!;
        var profile = u.TryGetProperty("profile", out var p) ? p : default;
        var enc = Uri.EscapeDataString(id);
        var factors = new List<object>();
        if ((await TryGetAsync($"/api/v1/users/{enc}/factors", ct)).Json is { ValueKind: JsonValueKind.Array } fs)
            foreach (var f in fs.EnumerateArray().Take(20))
                factors.Add(new { type = Str(f, "factorType"), provider = Str(f, "provider"), status = Str(f, "status"), created = Str(f, "created") });
        var groups = new List<string>();
        if ((await TryGetAsync($"/api/v1/users/{enc}/groups?limit=50", ct)).Json is { ValueKind: JsonValueKind.Array } gs)
            foreach (var g in gs.EnumerateArray().Take(50))
                if (g.TryGetProperty("profile", out var gp) && Str(gp, "name") is { } gn) groups.Add(gn);
        var (roles, rolesStatus) = await TryGetAsync($"/api/v1/users/{enc}/roles", ct);
        List<string>? admin = null;
        if (roles is { ValueKind: JsonValueKind.Array } rs) admin = rs.EnumerateArray().Select(r => Str(r, "type") ?? Str(r, "label")).OfType<string>().Take(20).ToList();
        return new UserContext(id, Str(profile, "login"), Str(profile, "email"), Str(profile, "secondEmail"),
            Str(profile, "displayName") ?? string.Join(' ', new[] { Str(profile, "firstName"), Str(profile, "lastName") }.OfType<string>()),
            Str(u, "status"), Str(u, "lastLogin"), Str(u, "passwordChanged"), factors, groups, admin, rolesStatus is not (401 or 403));
    }

    /// <summary>System Log events (newest first, at most <paramref name="limit"/>, capped at 100) for a SCIM filter in a time window.</summary>
    public async Task<IReadOnlyList<object>> LogsAsync(string filter, DateTimeOffset since, DateTimeOffset until, int limit, CancellationToken ct)
    {
        var q = $"/api/v1/logs?since={Uri.EscapeDataString(since.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))}&until={Uri.EscapeDataString(until.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))}"
                + $"&filter={Uri.EscapeDataString(filter)}&limit={Math.Clamp(limit, 1, 100)}&sortOrder=DESCENDING";
        var json = await GetAsync(q, ct);
        var list = new List<object>();
        if (json is not { ValueKind: JsonValueKind.Array } arr) return list;
        foreach (var e in arr.EnumerateArray().Take(Math.Clamp(limit, 1, 100)))
        {
            var actor = e.TryGetProperty("actor", out var a) ? a : default;
            var client = e.TryGetProperty("client", out var c) ? c : default;
            var outcome = e.TryGetProperty("outcome", out var o) ? o : default;
            var geo = client.ValueKind == JsonValueKind.Object && client.TryGetProperty("geographicalContext", out var g) ? g : default;
            list.Add(new
            {
                published = Str(e, "published"),
                event_type = Str(e, "eventType"),
                display_message = Clip(Str(e, "displayMessage"), 300),
                severity = Str(e, "severity"),
                outcome = Str(outcome, "result"),
                outcome_reason = Clip(Str(outcome, "reason"), 300),
                actor = Str(actor, "alternateId"),
                ip = Str(client, "ipAddress"),
                user_agent = Clip(client.ValueKind == JsonValueKind.Object && client.TryGetProperty("userAgent", out var ua) ? Str(ua, "rawUserAgent") : null, 300),
                city = Str(geo, "city"),
                country = Str(geo, "country"),
            });
        }
        return list;
    }

    /// <summary>Cheapest read that proves the credential works (one user).</summary>
    public Task ProbeAsync(CancellationToken ct) => GetAsync("/api/v1/users?limit=1", ct);

    internal static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static string? Clip(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max];
}
