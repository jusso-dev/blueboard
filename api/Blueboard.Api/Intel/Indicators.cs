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
