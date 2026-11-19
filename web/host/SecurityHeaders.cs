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

    public static SecurityHeaders For(WebConfig cfg)
    {
        var api = cfg.ApiOrigin.GetLeftPart(UriPartial.Authority);
        var login = cfg.Authority.GetLeftPart(UriPartial.Authority);
        var csp = string.Join("; ",
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self' data:",
            $"connect-src 'self' {api} {login}",
            // MSAL renews tokens in a hidden iframe: Entra, which then redirects back to /redirect on this origin.
            $"frame-src 'self' {login}",
            "frame-ancestors 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'");
        KeyValuePair<string, string>[] common =
        [
            new("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
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
