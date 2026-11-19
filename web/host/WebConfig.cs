using System.Text.Json.Serialization;

namespace Blueboard.Web;

/// <summary>Settings from App Service app settings. All public: they identify the tenant, app and API, nothing more.</summary>
public sealed record WebConfig(PublicConfig Public, Uri ApiOrigin, Uri Authority)
{
    public static WebConfig FromEnvironment(bool development)
    {
        static string Env(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v
            ? v
            : throw new InvalidOperationException($"set {k}");

        var api = new Uri(Env("BLUEBOARD_API_URL").TrimEnd('/'));
        if (api.Scheme != Uri.UriSchemeHttps && !development)
            throw new InvalidOperationException("BLUEBOARD_API_URL must be https");
        var tenant = Env("BLUEBOARD_TENANT_ID");
        if (!Guid.TryParse(tenant, out _)) throw new InvalidOperationException("BLUEBOARD_TENANT_ID must be the tenant id (a GUID)");
        var clientId = Env("BLUEBOARD_CLIENT_ID");
        var authorityHost = Environment.GetEnvironmentVariable("BLUEBOARD_AUTHORITY_HOST") is { Length: > 0 } h ? h : "https://login.microsoftonline.com";
        var authority = new Uri($"{authorityHost.TrimEnd('/')}/{tenant}");
        var scope = Env("BLUEBOARD_API_SCOPE");
        return new WebConfig(
            new PublicConfig(tenant, clientId, authority.ToString(), $"{api}/api", scope),
            new Uri(api.GetLeftPart(UriPartial.Authority)),
            new Uri(authority.GetLeftPart(UriPartial.Authority)));
    }
}

public sealed record PublicConfig(
    [property: JsonPropertyName("tenant_id")] string TenantId,
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("authority")] string Authority,
    [property: JsonPropertyName("api_base_url")] string ApiBaseUrl,
    [property: JsonPropertyName("scope")] string Scope);

[JsonSerializable(typeof(PublicConfig))]
internal sealed partial class WebJson : JsonSerializerContext;
