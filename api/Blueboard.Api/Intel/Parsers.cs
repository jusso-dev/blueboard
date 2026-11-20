using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Blueboard.Api.Intel;

/// <summary>Tolerant JSON readers: a wrong type reads as missing, so upstream drift degrades instead of failing.</summary>
internal static class J
{
    public static string? Str(JsonElement e, string k) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static JsonElement? Obj(JsonElement e, string k) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Object ? v : null;

    public static IEnumerable<JsonElement> Arr(JsonElement e, string k) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray() : [];

    public static List<string> Strs(JsonElement e, string k, int max = 100) =>
        Arr(e, k).Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).Where(s => s.Length > 0).Take(max).ToList();

    public static bool? Bool(JsonElement e, string k) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null } : null;

    public static double? Num(JsonElement e, string k)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(k, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number) return v.GetDouble();
        return v.ValueKind == JsonValueKind.String && double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
    }

    public static DateTimeOffset? Date(string? s) =>
        s is not null && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var d) ? d : null;

    public static JsonArray Array(IEnumerable<string> xs) => new(xs.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());

    public static string? Cap(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max] + "…";

    /// <summary>Only absolute https (or http for reference lists) links are kept; anything else becomes null.</summary>
    public static string? SafeUrl(string? raw, bool allowHttp = false) =>
        Uri.TryCreate(raw, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || (allowHttp && u.Scheme == Uri.UriSchemeHttp)) && u.Host.Length > 0
            ? u.ToString() : null;
}

public sealed record ParseResult(IReadOnlyList<TiRecord> Records, int Skipped, DateTimeOffset? DataAsOf);

public sealed record PwnChange(string Hash, string Incident, string? IncidentTitle, string? Severity, string? Status, string? PatchStatus,
    string? Date, string Title, string? Url, string? SourceUrl);

public sealed record PwnTag(string Id, string Label, int Incidents);

/// <summary>pwn.watch JSON feeds (https://pwn.watch/llms.txt). Ported from Crosswire's apps/web/src/server/ti/pwnwatch.ts (MIT).</summary>
public static class PwnWatchParser
{
    public const string Base = "https://pwn.watch";
    public const string IncidentsUrl = Base + "/incidents.json";
    public const string ChangesUrl = Base + "/all/changes.json";
    public const string TagsUrl = Base + "/tags.json";
    public static string DetailUrl(string slug) => $"{Base}/i/{Uri.EscapeDataString(slug)}.json";

    public static ParseResult Incidents(string json, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var list = new List<TiRecord>();
        var skipped = 0;
        foreach (var i in J.Arr(root, "incidents"))
        {
            var slug = J.Str(i, "slug");
            var title = J.Str(i, "title");
            if (i.ValueKind != JsonValueKind.Object || slug is not { Length: > 0 and <= 200 } || title is null || slug.Contains('/')) { skipped++; continue; }
            if (J.Bool(i, "isExample") == true) continue;
            var cves = J.Strs(i, "cveIds").Select(Indicators.NormaliseCve).OfType<string>().Distinct().ToList();
            var tags = J.Strs(i, "tags").Concat(J.Strs(i, "stacks")).Select(t => t.ToLowerInvariant()).Distinct().ToList();
            var product = J.Str(i, "product");
            var data = new JsonObject
            {
                ["slug"] = slug,
                ["category"] = J.Str(i, "category"),
                ["status"] = J.Str(i, "status"),
                ["severity"] = J.Str(i, "severity"),
                ["patch_status"] = J.Str(i, "patchStatus"),
                ["product"] = product,
                ["tags"] = J.Array(tags),
                ["cve_ids"] = J.Array(cves),
                ["affected_versions"] = J.Array(J.Strs(i, "affectedVersions", 20).Select(v => J.Cap(v, 300)!)),
                ["fixed_versions"] = J.Array(J.Strs(i, "fixedVersions", 20).Select(v => J.Cap(v, 300)!)),
                ["started_at"] = J.Str(i, "startedAt"),
                ["closed_at"] = J.Str(i, "closedAt"),
                ["summary"] = J.Cap(J.Str(i, "summary"), 4000),
            };
            var keys = new List<(string, string)>();
            keys.AddRange(cves.Select(c => ("cve", c)));
            keys.AddRange(tags.Select(t => ("tag", t)));
            if (product is { Length: > 0 }) keys.Add(("product", product.ToLowerInvariant()));
            list.Add(new TiRecord(Sources.PwnWatch, slug, "incident", title, J.Str(i, "severity"),
                J.SafeUrl(J.Str(i, "url")) ?? $"{Base}/i/{Uri.EscapeDataString(slug)}", IncidentsUrl, data,
                J.Date(J.Str(i, "startedAt")), J.Date(J.Str(i, "updatedAt")), retrievedAt, keys));
        }
        return new ParseResult(list, skipped, J.Date(J.Str(root, "generatedAt")));
    }

    public static (IReadOnlyList<PwnChange> Changes, int Skipped) Changes(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var list = new List<PwnChange>();
        var skipped = 0;
        foreach (var c in J.Arr(doc.RootElement, "changes"))
        {
            var incident = J.Str(c, "incident");
            var title = J.Str(c, "title");
            if (incident is not { Length: > 0 } || title is null) { skipped++; continue; }
            var date = J.Str(c, "date");
            list.Add(new PwnChange(ChangeHash(incident, date, title), incident, J.Str(c, "incidentTitle"), J.Str(c, "severity"), J.Str(c, "status"),
                J.Str(c, "patchStatus"), date, title, J.SafeUrl(J.Str(c, "url")), J.SafeUrl(J.Str(c, "sourceUrl"))));
        }
        return (list, skipped);
    }

    /// <summary>Upstream changes have no id: hash incident, date and title, as Crosswire does.</summary>
    public static string ChangeHash(string incident, string? date, string title) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{incident}|{date ?? ""}|{title}")))[..32];

    public static (IReadOnlyList<PwnTag> Tags, int Skipped) Tags(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var list = new List<PwnTag>();
        var skipped = 0;
        foreach (var t in J.Arr(doc.RootElement, "tags"))
        {
            var id = J.Str(t, "id");
            if (id is not { Length: > 0 and <= 100 }) { skipped++; continue; }
            list.Add(new PwnTag(id.ToLowerInvariant(), J.Str(t, "label") ?? id, (int)(J.Num(t, "incidents") ?? 0)));
        }
        return (list, skipped);
    }

    /// <summary>The per-incident file: only the agent brief is used, and it is shown to people as quoted, untrusted text.</summary>
    public static string? AgentBrief(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return J.Cap(J.Str(doc.RootElement, "agentBrief"), 12000);
    }
}

/// <summary>CISA Known Exploited Vulnerabilities catalogue (CC0 1.0). Ported from Crosswire's ti/kev.ts (MIT).</summary>
public static class KevParser
{
    public const string Url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    public static string PageUrl(string cve) => $"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}";

    public static ParseResult Parse(string json, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var list = new List<TiRecord>();
        var skipped = 0;
        foreach (var v in J.Arr(doc.RootElement, "vulnerabilities"))
        {
            var cve = Indicators.NormaliseCve(J.Str(v, "cveID"));
            if (cve is null) { skipped++; continue; }
            var product = J.Str(v, "product");
            var vendor = J.Str(v, "vendorProject");
            var data = new JsonObject
            {
                ["vendor"] = vendor,
                ["product"] = product,
                ["date_added"] = J.Str(v, "dateAdded"),
                ["due_date"] = J.Str(v, "dueDate"),
                ["required_action"] = J.Cap(J.Str(v, "requiredAction"), 2000),
                ["short_description"] = J.Cap(J.Str(v, "shortDescription"), 2000),
                ["known_ransomware"] = string.Equals(J.Str(v, "knownRansomwareCampaignUse"), "Known", StringComparison.OrdinalIgnoreCase),
                ["cwes"] = J.Array(J.Strs(v, "cwes", 20)),
            };
            var keys = new List<(string, string)> { ("cve", cve), ("tag", "cisa-kev") };
            if (product is { Length: > 0 }) keys.Add(("product", product.ToLowerInvariant()));
            if (vendor is { Length: > 0 }) keys.Add(("vendor", vendor.ToLowerInvariant()));
            list.Add(new TiRecord(Sources.Kev, cve, "cve", J.Str(v, "vulnerabilityName"), "known exploited", PageUrl(cve), Url, data,
                J.Date(J.Str(v, "dateAdded")), null, retrievedAt, keys));
        }
        return new ParseResult(list, skipped, J.Date(J.Str(doc.RootElement, "dateReleased")));
    }
}

/// <summary>FIRST EPSS API: probability of exploitation in the next 30 days.</summary>
public static class EpssParser
{
    public const string Api = "https://api.first.org/data/v1/epss";
    public const int BatchSize = 100;
    public static string Url(IEnumerable<string> cves) => $"{Api}?cve={string.Join(',', cves)}";

    /// <summary>One record per requested CVE: found with score and percentile, or a cached "no score".</summary>
    public static IReadOnlyList<TiRecord> Parse(string json, IReadOnlyCollection<string> requested, string sourceUrl, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var found = new Dictionary<string, TiRecord>();
        foreach (var d in J.Arr(doc.RootElement, "data"))
        {
            var cve = Indicators.NormaliseCve(J.Str(d, "cve"));
            if (cve is null || !requested.Contains(cve)) continue;
            var epss = J.Num(d, "epss");
            var pct = J.Num(d, "percentile");
            if (epss is not (>= 0 and <= 1) || pct is not (>= 0 and <= 1)) continue;
            found[cve] = new TiRecord(Sources.Epss, cve, "cve", null, null, "https://www.first.org/epss/", sourceUrl,
                new JsonObject { ["epss"] = epss, ["percentile"] = pct, ["date"] = J.Str(d, "date") },
                J.Date(J.Str(d, "date")), null, retrievedAt, [("cve", cve)]);
        }
        return requested.Select(c => found.GetValueOrDefault(c)
                ?? new TiRecord(Sources.Epss, c, "cve", null, null, "https://www.first.org/epss/", sourceUrl, new JsonObject(), null, null, retrievedAt, [("cve", c)], Found: false))
            .ToList();
    }
}

/// <summary>NVD CVE API 2.0. "This product uses data from the NVD API but is not endorsed or certified by the NVD."</summary>
public static class NvdParser
{
    public static string Url(string cve) => $"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}";
    public static string PageUrl(string cve) => $"https://nvd.nist.gov/vuln/detail/{cve}";

    public static TiRecord Parse(string json, string cve, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var item = J.Arr(doc.RootElement, "vulnerabilities").Select(v => J.Obj(v, "cve")).FirstOrDefault(c => c is { } x && J.Str(x, "id") == cve);
        if (item is not { } c)
            return new TiRecord(Sources.Nvd, cve, "cve", null, null, PageUrl(cve), Url(cve), new JsonObject(), null, null, retrievedAt, [("cve", cve)], Found: false);

        JsonObject? cvss = null;
        var metrics = J.Obj(c, "metrics");
        foreach (var name in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
        {
            if (metrics is not { } m) break;
            var all = J.Arr(m, name).ToList();
            var pick = all.FirstOrDefault(x => J.Str(x, "type") == "Primary");
            if (pick.ValueKind != JsonValueKind.Object) pick = all.FirstOrDefault();
            if (pick.ValueKind != JsonValueKind.Object || J.Obj(pick, "cvssData") is not { } d) continue;
            cvss = new JsonObject
            {
                ["version"] = J.Str(d, "version"),
                ["vector"] = J.Str(d, "vectorString"),
                ["score"] = J.Num(d, "baseScore"),
                ["severity"] = J.Str(d, "baseSeverity") ?? J.Str(pick, "baseSeverity"),
                ["source"] = J.Str(pick, "source"),
            };
            break;
        }
        var cwes = J.Arr(c, "weaknesses").SelectMany(w => J.Arr(w, "description")).Select(d => J.Str(d, "value"))
            .OfType<string>().Where(v => v.StartsWith("CWE-", StringComparison.Ordinal)).Distinct().Take(10).ToList();
        var refs = J.Arr(c, "references").Select(r => J.SafeUrl(J.Str(r, "url"), allowHttp: true)).OfType<string>().Distinct().Take(10).ToList();
        var desc = J.Arr(c, "descriptions").FirstOrDefault(d => J.Str(d, "lang") == "en");
        var data = new JsonObject
        {
            ["cvss"] = cvss,
            ["cwes"] = J.Array(cwes),
            ["references"] = J.Array(refs),
            ["published"] = J.Str(c, "published"),
            ["last_modified"] = J.Str(c, "lastModified"),
            ["vuln_status"] = J.Str(c, "vulnStatus"),
            ["description"] = J.Cap(desc.ValueKind == JsonValueKind.Object ? J.Str(desc, "value") : null, 2000),
            ["notice"] = Sources.NvdNotice,
        };
        var keys = new List<(string, string)> { ("cve", cve) };
        keys.AddRange(cwes.Select(w => ("cwe", w)));
        return new TiRecord(Sources.Nvd, cve, "cve", null, cvss?["severity"]?.GetValue<string>()?.ToLowerInvariant(), PageUrl(cve), Url(cve), data,
            J.Date(J.Str(c, "published")), J.Date(J.Str(c, "lastModified")), retrievedAt, keys);
    }
}

/// <summary>OSV.dev vulnerability API. GitHub advisories (GHSA, CC-BY-4.0) arrive through OSV, so there is no separate GitHub fetcher.</summary>
public static class OsvParser
{
    public static string Url(string id) => $"https://api.osv.dev/v1/vulns/{id}";
    public static string PageUrl(string id) => $"https://osv.dev/vulnerability/{id}";

    public static TiRecord NotFound(string id, DateTimeOffset retrievedAt) =>
        new(Sources.Osv, id, "cve", null, null, PageUrl(id), Url(id), new JsonObject(), null, null, retrievedAt, [(KeyKind(id), id)], Found: false);

    public static string KeyKind(string id) => id.StartsWith("GHSA-", StringComparison.Ordinal) ? "ghsa" : "cve";

    public static TiRecord Parse(string json, string lookupId, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var o = doc.RootElement;
        var id = J.Str(o, "id") ?? lookupId;
        var aliases = J.Strs(o, "aliases", 20);
        var packages = Packages(o);
        var dbs = J.Obj(o, "database_specific");
        var data = new JsonObject
        {
            ["id"] = id,
            ["aliases"] = J.Array(aliases),
            ["summary"] = J.Cap(J.Str(o, "summary") ?? J.Str(o, "details"), 1000),
            ["published"] = J.Str(o, "published"),
            ["modified"] = J.Str(o, "modified"),
            ["packages"] = packages,
            ["cvss"] = J.Arr(o, "severity").Select(s => J.Str(s, "score")).OfType<string>().FirstOrDefault(),
            ["cwes"] = dbs is { } d ? J.Array(J.Strs(d, "cwe_ids", 10)) : new JsonArray(),
        };
        var keys = new List<(string, string)> { (KeyKind(lookupId), lookupId) };
        foreach (var a in aliases.Append(id))
        {
            if (Indicators.NormaliseCve(a) is { } c) keys.Add(("cve", c));
            else if (Indicators.Normalise("ghsa", a) is { } g) keys.Add(("ghsa", g));
        }
        var severity = dbs is { } db2 ? J.Str(db2, "severity")?.ToLowerInvariant() : null;
        return new TiRecord(Sources.Osv, lookupId, "cve", J.Cap(J.Str(o, "summary"), 300), severity, PageUrl(id), Url(lookupId), data,
            J.Date(J.Str(o, "published")), J.Date(J.Str(o, "modified")), retrievedAt, keys);
    }

    /// <summary>Affected packages with the versions that fix them (ECOSYSTEM and SEMVER ranges only; git commits aren't versions).</summary>
    public static JsonArray Packages(JsonElement o)
    {
        var arr = new JsonArray();
        foreach (var a in J.Arr(o, "affected").Take(30))
        {
            if (J.Obj(a, "package") is not { } p || J.Str(p, "name") is not { } name) continue;
            var fixedVersions = J.Arr(a, "ranges").Where(r => J.Str(r, "type") is "ECOSYSTEM" or "SEMVER")
                .SelectMany(r => J.Arr(r, "events")).Select(e => J.Str(e, "fixed")).OfType<string>().Distinct().Take(10).ToList();
            arr.Add(new JsonObject { ["ecosystem"] = J.Str(p, "ecosystem"), ["name"] = name, ["fixed"] = J.Array(fixedVersions) });
        }
        return arr;
    }

    /// <summary>True when the record names a package with a fixed version (otherwise follow its GHSA alias).</summary>
    public static bool HasFixedPackages(TiRecord r) =>
        r.Data["packages"] is JsonArray a && a.Any(p => p?["fixed"] is JsonArray f && f.Count > 0);
}
