using System.Text.RegularExpressions;
using Blueboard.Api.Core;

namespace Blueboard.Api.Intel;

/// <summary>What a watch is matched against: the searchable parts of one record.</summary>
public sealed record Watchable(string Title, string Text, IReadOnlyCollection<string> Tags, IReadOnlyCollection<string> Cves, IReadOnlyCollection<string> Products);

/// <summary>
/// Watch rules, ported from Crosswire's matcher (MIT): cve and tag match exactly; product and keyword match a whole
/// word, case-insensitively (product against the record's product names, then its title).
/// </summary>
public static class Watches
{
    public static readonly string[] Kinds = ["tag", "product", "cve", "keyword"];

    public static string Normalise(string kind, string value)
    {
        if (!Kinds.Contains(kind)) throw new BoardException("kind must be tag, product, cve or keyword");
        var v = Regex.Replace(value.Trim(), @"\s+", " ");
        if (kind == "cve") return Indicators.NormaliseCve(v) ?? throw new BoardException("invalid CVE id");
        v = v.ToLowerInvariant();
        if (v.Length is < 2 or > 200 || v.Any(char.IsControl)) throw new BoardException("watch value must be 2–200 characters");
        if (kind == "keyword" && v.Length < 3) throw new BoardException("keywords must be at least 3 characters");
        return v;
    }

    public static bool Matches(Watch w, Watchable r) => w.Kind switch
    {
        "cve" => r.Cves.Contains(w.Value),
        "tag" => r.Tags.Contains(w.Value),
        "product" => r.Products.Any(p => Word(w.Value).IsMatch(p)) || Word(w.Value).IsMatch(r.Title),
        "keyword" => Word(w.Value).IsMatch(r.Title) || Word(w.Value).IsMatch(r.Text),
        _ => false,
    };

    public static IReadOnlyList<string> Matching(IEnumerable<Watch> watches, Watchable r) =>
        watches.Where(w => w.Enabled && Matches(w, r)).Select(w => $"{w.Kind}:{w.Value}").ToList();

    private static Regex Word(string v) => new($"(^|[^a-z0-9]){Regex.Escape(v)}($|[^a-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
}
