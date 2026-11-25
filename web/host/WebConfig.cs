using System.Text.Json.Serialization;

namespace Blueboard.Web;

/// <summary>Settings from App Service app settings. All public: they identify the tenant, app and API, nothing more.</summary>
public sealed record WebConfig(PublicConfig Public, Uri ApiOrigin, Uri Authority)
{
    public bool DevAuth => Public.Mode == "dev";

    public static WebConfig FromEnvironment(bool development) =>
        FromEnvironment(development, k => Environment.GetEnvironmentVariable(k));

    public static WebConfig FromEnvironment(bool development, Func<string, string?> source)
    {
        string? Opt(string k) => source(k) is { Length: > 0 } v ? v : null;
        string Env(string k) => Opt(k) ?? throw new InvalidOperationException($"set {k}");

        // Local demo only: the SPA uses /dev-login and the API's DEV_AUTH. App Service always sets WEBSITE_INSTANCE_ID.
        if (Opt("BLUEBOARD_DEV_AUTH") is "true")
        {
            if (Opt("WEBSITE_INSTANCE_ID") is not null) throw new InvalidOperationException("BLUEBOARD_DEV_AUTH must not be enabled in Azure");
            var devApi = new Uri((Opt("BLUEBOARD_API_URL") ?? "http://localhost:7071").TrimEnd('/'));
            if (devApi.Scheme != Uri.UriSchemeHttp && devApi.Scheme != Uri.UriSchemeHttps)
                throw new InvalidOperationException("BLUEBOARD_API_URL must be http(s)");
            var none = new Uri("https://login.invalid");
            var origin = devApi.GetLeftPart(UriPartial.Authority);
            return new WebConfig(new PublicConfig("dev", null, null, null, $"{origin}/api", null), new Uri(origin), none);
        }

        var api = new Uri(Env("BLUEBOARD_API_URL").TrimEnd('/'));
        if (api.Scheme != Uri.UriSchemeHttps && !development)
            throw new InvalidOperationException("BLUEBOARD_API_URL must be https");
        var tenant = Env("BLUEBOARD_TENANT_ID");
        if (!Guid.TryParse(tenant, out _)) throw new InvalidOperationException("BLUEBOARD_TENANT_ID must be the tenant id (a GUID)");
        var clientId = Env("BLUEBOARD_CLIENT_ID");
        var authorityHost = Opt("BLUEBOARD_AUTHORITY_HOST") ?? "https://login.microsoftonline.com";
        var authority = new Uri($"{authorityHost.TrimEnd('/')}/{tenant}");
        var scope = Env("BLUEBOARD_API_SCOPE");
        return new WebConfig(
            // Uri.ToString() adds a trailing slash to a bare origin, so build from the trimmed string, not the Uri.
            new PublicConfig("entra", tenant, clientId, authority.ToString(), $"{api.ToString().TrimEnd('/')}/api", scope),
            new Uri(api.GetLeftPart(UriPartial.Authority)),
            new Uri(authority.GetLeftPart(UriPartial.Authority)));
    }
}

/// <summary>What /config.json tells the SPA. mode "dev" is only ever served by a local demo host.</summary>
public sealed record PublicConfig(
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("tenant_id")] string? TenantId,
    [property: JsonPropertyName("client_id")] string? ClientId,
    [property: JsonPropertyName("authority")] string? Authority,
    [property: JsonPropertyName("api_base_url")] string ApiBaseUrl,
    [property: JsonPropertyName("scope")] string? Scope);

[JsonSerializable(typeof(PublicConfig))]
internal sealed partial class WebJson : JsonSerializerContext;
