using System.Security.Claims;
using Blueboard.Api.Core;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Blueboard.Api.Auth;

/// <summary>Validates Entra ID access tokens for the board API (issuer, audience, tenant, signature, lifetime).</summary>
public sealed class TokenValidator
{
    private readonly Settings _settings;
    private readonly ConfigurationManager<OpenIdConnectConfiguration>? _config;
    private readonly JsonWebTokenHandler _handler = new();

    public TokenValidator(Settings settings)
    {
        _settings = settings;
        if (settings.TenantId is { } tenant)
        {
            _config = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true });
        }
    }

    public async Task<CallerIdentity> ValidateAsync(string token, CancellationToken ct = default)
    {
        if (_config is null || _settings.ApiAudience is null)
            throw BoardException.Unauthorized("Entra auth is not configured (AZURE_TENANT_ID, BOARD_API_AUDIENCE)");
        var oidc = await _config.GetConfigurationAsync(ct);
        var tenant = _settings.TenantId!;
        var audiences = new List<string> { _settings.ApiAudience };
        if (_settings.ApiClientId is { } cid) audiences.Add(cid);

        var result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuers = [$"https://login.microsoftonline.com/{tenant}/v2.0", $"https://sts.windows.net/{tenant}/"],
            ValidAudiences = audiences,
            IssuerSigningKeys = oidc.SigningKeys,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
            RequireSignedTokens = true,
        });
        if (!result.IsValid) throw BoardException.Unauthorized("invalid token");
        var claims = result.ClaimsIdentity;
        if (claims.FindFirst("tid")?.Value != tenant) throw BoardException.Unauthorized("wrong tenant");
        return FromClaims(claims);
    }

    internal static CallerIdentity FromClaims(ClaimsIdentity claims)
    {
        string? Get(string type) => claims.FindFirst(type)?.Value;
        var oid = Get("oid") ?? Get("http://schemas.microsoft.com/identity/claims/objectidentifier")
                  ?? throw BoardException.Unauthorized("token has no oid");
        // App-only (workload identity) tokens have idtyp=app and no scp / preferred_username.
        var isApp = Get("idtyp") == "app" || (Get("scp") is null && Get("preferred_username") is null);
        var kind = isApp ? "agent" : "human";
        var roles = claims.FindAll("roles").Concat(claims.FindAll(ClaimTypes.Role)).Select(c => c.Value);
        return new CallerIdentity(
            oid,
            Get("azp") ?? Get("appid"),
            kind,
            Get("name") ?? Get("app_displayname") ?? Get("azp") ?? oid,
            Get("preferred_username"),
            MapRoles(roles, kind));
    }

    /// <summary>Entra app roles → board roles. Agents can never approve: approval is for people.</summary>
    internal static string[] MapRoles(IEnumerable<string> appRoles, string kind)
    {
        var mapped = appRoles.Select(r => Roles.FromAppRole.GetValueOrDefault(r)).OfType<string>().Distinct();
        if (kind == "agent") mapped = mapped.Where(r => r != Roles.Approver && r != Roles.Admin);
        return mapped.Order(StringComparer.Ordinal).ToArray();
    }
}
