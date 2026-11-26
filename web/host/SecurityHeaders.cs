namespace Blueboard.Web;

/// <summary>
/// Response headers for every page. The CSP allows scripts only from this origin, network calls only to
/// this origin, the board API and Entra sign-in, and frames only for MSAL's silent token renewal.
/// </summary>
public sealed class SecurityHeaders
{
    private readonly KeyValuePair<string, string>[] _common;
    private readonly KeyValuePair<string, string>[] _page;

    private SecurityHeaders(KeyValuePair<string, string>[] common, KeyValuePair<string, string>[] page) => (_common, _page) = (common, page);

    private const string GifImgSources =
        "https://media.giphy.com https://media0.giphy.com https://media1.giphy.com https://media2.giphy.com https://media3.giphy.com https://media4.giphy.com https://i.giphy.com https://media.tenor.com https://c.tenor.com";

    public static SecurityHeaders For(WebConfig cfg)
    {
        var api = cfg.ApiOrigin.GetLeftPart(UriPartial.Authority);
        // The local demo has no Entra sign-in, so nothing to allow for it.
        var login = cfg.DevAuth ? "" : " " + cfg.Authority.GetLeftPart(UriPartial.Authority);
        var imgSrc = cfg.GifsEnabled ? $"img-src 'self' data: {GifImgSources}" : "img-src 'self' data:";
        var csp = string.Join("; ",
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            imgSrc,
            "font-src 'self' data:",
            $"connect-src 'self' {api}{login}",
            // MSAL renews tokens in a hidden iframe: Entra, which then redirects back to /redirect on this origin.
            $"frame-src 'self'{login}",
            "frame-ancestors 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'");
        KeyValuePair<string, string>[] common =
        [
            // Not on the local demo: HSTS for http://localhost would pin every local site to https.
            .. cfg.DevAuth ? [] : new KeyValuePair<string, string>[] { new("Strict-Transport-Security", "max-age=31536000; includeSubDomains") },
            new("X-Content-Type-Options", "nosniff"),
            new("Referrer-Policy", "no-referrer"),
            new("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
            new("Cross-Origin-Resource-Policy", "same-origin"),
        ];
        KeyValuePair<string, string>[] page =
        [
            new("Content-Security-Policy", csp),
            new("X-Frame-Options", "SAMEORIGIN"),
        ];
        return new SecurityHeaders(common, page);
    }

    /// <summary>HTML and API-ish paths get the CSP; static assets only need the common set.</summary>
    public IEnumerable<KeyValuePair<string, string>> ForPath(string path) =>
        path.StartsWith("/assets/", StringComparison.Ordinal) ? _common : _common.Concat(_page);
}
