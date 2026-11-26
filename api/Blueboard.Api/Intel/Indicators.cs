using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;

namespace Blueboard.Api.Intel;

/// <summary>An intel lookup key: a CVE id or an indicator, validated and normalised for its kind.</summary>
public sealed record IntelKey(string Kind, string Value)
{
    public bool IsCve => Kind == "cve";
}

/// <summary>
/// Validation for everything that reaches KQL, a Graph path or a STIX pattern. Values that don't match
/// their kind are refused, so builders only ever see a narrow, known character set.
/// </summary>
public static partial class Indicators
{
    public static readonly string[] Kinds = ["cve", "ghsa", "ip", "domain", "url", "sha256", "sha1", "md5", "email"];

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$")] private static partial Regex CveId();
    [GeneratedRegex(@"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")] private static partial Regex GhsaId();
    [GeneratedRegex(@"\bCVE-\d{4}-\d{4,}\b", RegexOptions.IgnoreCase)] private static partial Regex CveInText();
    [GeneratedRegex(@"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")] private static partial Regex Domain();
    [GeneratedRegex("^[0-9a-f]{64}$")] private static partial Regex Sha256();
    [GeneratedRegex("^[0-9a-f]{40}$")] private static partial Regex Sha1();
    [GeneratedRegex("^[0-9a-f]{32}$")] private static partial Regex Md5();
    [GeneratedRegex(@"^[a-z0-9._%+-]{1,64}@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")] private static partial Regex Email();

    public static string? NormaliseCve(string? input)
    {
        var v = input?.Trim().ToUpperInvariant();
        return v is not null && CveId().IsMatch(v) ? v : null;
    }

    public static bool IsCve(string? input) => NormaliseCve(input) is not null;

    /// <summary>Distinct CVE ids mentioned in free text, upper case, in order of appearance.</summary>
    public static IReadOnlyList<string> CvesIn(string? text) =>
        text is null ? [] : CveInText().Matches(text).Select(m => m.Value.ToUpperInvariant()).Distinct().ToList();

    /// <summary>
    /// True when the input is a private, loopback, link-local, CGNAT, multicast, unspecified or otherwise non-routable
    /// IP address (RFC 1918, RFC 6598, RFC 4193, link-local, loopback, IPv4-mapped IPv6, etc.). RFC 5737 documentation
    /// ranges (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32) are treated as routable examples for demo/tests.
    /// </summary>
    public static bool IsPrivateIp(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return false;
        var trimmed = raw.Trim().Trim('[', ']');
        if (!IPAddress.TryParse(trimmed, out var ip)) return false;
        return IsPrivateIp(ip);
    }

    public static bool IsPrivateIp(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Broadcast))
            return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 0                                        // 0.0.0.0/8 unspecified
                || b[0] == 10                                       // 10.0.0.0/8 RFC 1918
                || b[0] == 127                                      // 127.0.0.0/8 loopback
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)       // 100.64.0.0/10 CGNAT / Tailscale
                || (b[0] == 169 && b[1] == 254)                     // 169.254.0.0/16 link-local / cloud metadata
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)        // 172.16.0.0/12 RFC 1918
                || (b[0] == 192 && b[1] == 168)                     // 192.168.0.0/16 RFC 1918
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)          // 192.0.0.0/24 IETF protocol assignments
                || (b[0] == 198 && (b[1] == 18 || b[1] == 19))      // 198.18.0.0/15 benchmarking
                || b[0] >= 224;                                     // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6UniqueLocal || ip.IsIPv6Teredo)
                return true;
            var b = ip.GetAddressBytes();
            // Documentation prefix 2001:db8::/32 is allowed for demo/test examples; all other non-global-unicast ranges are private/non-routable.
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false;
            if ((b[0] & 0xE0) != 0x20) return true;                 // outside 2000::/3 (::/96, 64:ff9b::/96, 100::/64, etc.)
            if (b[0] == 0x20 && b[1] == 0x02) return true;          // 2002::/16 6to4 (can embed RFC1918/loopback IPv4)
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) return true; // 2001::/32 Teredo
            return false;
        }
        return true;
    }

    /// <summary>True when an intel key is a private/non-routable IP or a URL whose host is a private/non-routable IP.</summary>
    public static bool IsPrivateIntelKey(IntelKey key) => key.Kind switch
    {
        "ip" => IsPrivateIp(key.Value),
        "url" => Uri.TryCreate(key.Value, UriKind.Absolute, out var u) && IsPrivateIp(u.Host),
        _ => false,
    };

    /// <summary>Validated, normalised value for a kind, or null if it doesn't fit.</summary>
    public static string? Normalise(string kind, string? raw)
    {
        if (raw is null) return null;
        var v = raw.Trim();
        if (v.Length is 0 or > 2048 || v.Any(char.IsControl)) return null;
        switch (kind)
        {
            case "cve": return NormaliseCve(v);
            case "ghsa":
                var g = "GHSA" + v[(v.Length >= 4 ? 4 : 0)..].ToLowerInvariant();
                return GhsaId().IsMatch(g) ? g : null;
            case "ip":
                return IPAddress.TryParse(v, out var ip) && ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6
                       && (ip.AddressFamily == AddressFamily.InterNetworkV6 || v.Count(c => c == '.') == 3)
                    ? ip.ToString() : null;
            case "domain":
                var d = v.TrimEnd('.').ToLowerInvariant();
                return Domain().IsMatch(d) ? d : null;
            case "url":
                if (!Uri.TryCreate(v, UriKind.Absolute, out var u) || u.Scheme is not ("http" or "https") || u.Host.Length == 0) return null;
                // Double quotes, backslashes and spaces have no business in an indicator URL. A single quote is legal in a URL
                // and is escaped by the KQL and STIX literal builders.
                return v.IndexOfAny(['"', '\\', ' ', '<', '>']) >= 0 ? null : v;
            case "sha256": return Sha256().IsMatch(v.ToLowerInvariant()) ? v.ToLowerInvariant() : null;
            case "sha1": return Sha1().IsMatch(v.ToLowerInvariant()) ? v.ToLowerInvariant() : null;
            case "md5": return Md5().IsMatch(v.ToLowerInvariant()) ? v.ToLowerInvariant() : null;
            case "email": return Email().IsMatch(v.ToLowerInvariant()) ? v.ToLowerInvariant() : null;
            default: return null;
        }
    }

    /// <summary>Works out the kind of a free-form key (what someone types into /intel), or throws.</summary>
    public static IntelKey Parse(string? raw, string? kind = null)
    {
        if (kind is not null)
        {
            if (!Kinds.Contains(kind)) throw new BoardException($"kind must be one of {string.Join(", ", Kinds)}");
            return Normalise(kind, raw) is { } v ? new IntelKey(kind, v) : throw new BoardException($"invalid {kind}");
        }
        foreach (var k in new[] { "cve", "ghsa", "sha256", "sha1", "md5", "ip", "email", "url", "domain" })
            if (Normalise(k, raw) is { } v) return new IntelKey(k, v);
        throw new BoardException("key must be a CVE id (CVE-YYYY-NNNN), a GHSA id, an IP, domain, URL, email or file hash");
    }
}
