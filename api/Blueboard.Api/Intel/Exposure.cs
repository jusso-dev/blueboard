using System.Globalization;
using System.Text.Json;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Contracts;

namespace Blueboard.Api.Intel;

/// <summary>
/// Exposure prioritisation (list_exposure_recommendations, get_attack_paths, prioritize_exposures). Read only: every
/// query is built by the board (no caller KQL), and remediation goes through the normal request flow.
/// </summary>
public sealed class ExposureService(Audit audit, MsClient ms, Enrichment enrich, IntelService intel, IntelStore store, RateLimiter? limiter = null)
{
    /// <summary>One row per (CVE, device) for the worst vulnerabilities, with device context. Board-built; no caller input.</summary>
    public const string PrioritiesKql = """
        DeviceTvmSoftwareVulnerabilities
        | where VulnerabilitySeverityLevel in ("Critical", "High", "Medium")
        | summarize Software = take_any(strcat(SoftwareVendor, " ", SoftwareName, " ", SoftwareVersion)), Remediation = take_any(RecommendedSecurityUpdate)
            by CveId, DeviceId, DeviceName, Severity = VulnerabilitySeverityLevel
        | join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable) on CveId
        | join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, AssetValue, AadDeviceId) by DeviceId) on DeviceId
        | project CveId, DeviceId, DeviceName, Severity, CvssScore, IsExploitAvailable, IsInternetFacing, AssetValue, AadDeviceId, Software, Remediation
        | take 5000
        """;

    /// <summary>
    /// Exposure graph: internet-facing or RCE-vulnerable nodes that reach a critical asset (criticality 0-1) in up to 3 hops.
    /// Property paths per Microsoft's Exposure Management examples (NodeProperties.rawData.*).
    /// </summary>
    public static string AttackPathsKql(bool internetFacingOnly, bool criticalOnly, int limit) => $$"""
        let entries = ExposureGraphNodes
            | extend raw = parse_json(tostring(NodeProperties)).rawData
            | extend Internet = isnotnull(raw.exposedToInternet) or tobool(raw.IsInternetFacing), Rce = isnotnull(raw.vulnerableToRCE)
            | where {{(internetFacingOnly ? "Internet" : "Internet or Rce")}}
            | project NodeId;
        let targets = ExposureGraphNodes
            | extend raw = parse_json(tostring(NodeProperties)).rawData
            | extend Criticality = toint(raw.criticalityLevel.criticalityLevel)
            | where {{(criticalOnly ? "isnotnull(Criticality) and Criticality <= 1" : "isnotnull(Criticality) and Criticality <= 3")}}
            | project NodeId;
        ExposureGraphEdges
        | make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
        | graph-match (s)-[e*1..3]->(t)
            where s.NodeId in (entries) and t.NodeId in (targets)
            project SourceName = s.NodeName, SourceLabel = s.NodeLabel, SourceId = s.NodeId, TargetName = t.NodeName, TargetLabel = t.NodeLabel,
                    TargetId = t.NodeId, TargetCriticality = toint(parse_json(tostring(t.NodeProperties)).rawData.criticalityLevel.criticalityLevel),
                    Hops = array_length(e), Edges = e.EdgeLabel
        | summarize Paths = count(), MinHops = min(Hops), Via = take_any(Edges) by SourceName, SourceLabel, SourceId, TargetName, TargetLabel, TargetId, TargetCriticality
        | order by TargetCriticality asc, MinHops asc, Paths desc
        | take {{Math.Clamp(limit, 1, 50)}}
        """;

    public async Task<object> RecommendationsAsync(Principal p, ExposureRecommendationsQuery q, CancellationToken ct = default)
    {
        p.Require(Roles.Hunter);
        if (limiter is not null) await limiter.TakeAsync(p, "lookup", ct);
        await audit.WriteAsync(p.Id, "exposure.recommendations", null, new { q.Status, q.ExploitableOnly, q.Limit }, ct);
        var filter = Uri.EscapeDataString($"status eq '{(q.Status == "Exception" ? "Exception" : "Active")}'");
        var res = await ms.SendAsync(MsApi.Defender, $"/api/recommendations?$filter={filter}&$top=500", ct: ct);
        var rows = res is { } r && r.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().ToList() : [];
        var shaped = rows
            .Where(x => !q.ExploitableOnly || Bool(x, "publicExploit"))
            .OrderByDescending(x => Num(x, "exposureImpact") ?? 0).ThenByDescending(x => Int(x, "exposedCriticalDevices")).ThenByDescending(x => Int(x, "exposedMachinesCount"))
            .Take(q.Limit)
            .Select(x => new
            {
                id = J.Str(x, "id"), name = J.Str(x, "recommendationName"), product = J.Str(x, "productName"), vendor = J.Str(x, "vendor"),
                category = J.Str(x, "recommendationCategory"), remediation_type = J.Str(x, "remediationType"), recommended_version = J.Str(x, "recommendedVersion"),
                weaknesses = Int(x, "weaknesses"), public_exploit = Bool(x, "publicExploit"), active_alert = Bool(x, "activeAlert"),
                exposed_devices = Int(x, "exposedMachinesCount"), exposed_critical_devices = Int(x, "exposedCriticalDevices"),
                exposure_impact = Num(x, "exposureImpact"), internet_facing = J.Strs(x, "tags").Contains("internetFacing"), tags = J.Strs(x, "tags"),
            }).ToList();
        return new { source = "Defender Vulnerability Management (GET /api/recommendations)", total = rows.Count, recommendations = shaped };
    }

    public async Task<object> AttackPathsAsync(Principal p, AttackPathsQuery q, CancellationToken ct = default)
    {
        p.Require(Roles.Hunter);
        if (limiter is not null) await limiter.TakeAsync(p, "hunt", ct);
        var rows = await enrich.RunBoardQueryAsync(p.Id, "exposure.attack_paths", AttackPathsKql(q.InternetFacingOnly, q.CriticalTargetsOnly, q.Limit), "P1D",
            new { q.InternetFacingOnly, q.CriticalTargetsOnly, q.Limit }, ct);
        return new
        {
            source = "Microsoft Security Exposure Management (ExposureGraphNodes / ExposureGraphEdges, preview tables)",
            paths = rows.Take(q.Limit).Select(x => new
            {
                source = new { name = J.Str(x, "SourceName"), label = J.Str(x, "SourceLabel"), id = J.Str(x, "SourceId") },
                target = new { name = J.Str(x, "TargetName"), label = J.Str(x, "TargetLabel"), id = J.Str(x, "TargetId"), criticality = Int(x, "TargetCriticality") },
                paths = Int(x, "Paths"), min_hops = Int(x, "MinHops"), via = x.TryGetProperty("Via", out var via) ? via : default,
            }),
            note = "Criticality 0 is the most critical. Empty results mean Exposure Management has no paths for these filters, or the tenant has no Exposure Management data.",
        };
    }

    public async Task<IReadOnlyList<ExposureItem>> PrioritizeAsync(Principal p, PrioritizeExposuresQuery q, CancellationToken ct = default)
    {
        p.Require(Roles.Hunter);
        if (limiter is not null) await limiter.TakeAsync(p, "hunt", ct);
        var only = q.CveIds is { Length: > 0 } ids ? Kql.ValidCves(ids).ToHashSet(StringComparer.OrdinalIgnoreCase) : null;
        var rows = await enrich.RunBoardQueryAsync(p.Id, "exposure.prioritize", PrioritiesKql, "P1D", new { q.Limit, cves = only }, ct);
        var open = await intel.OpenIncidentDevicesAsync(ct);
        var cves = rows.Select(r => J.Str(r, "CveId")).OfType<string>().Select(Indicators.NormaliseCve).OfType<string>().Distinct().Take(500).ToList();
        var kev = (await store.GetManyAsync(Sources.Kev, cves, ct)).Where(r => r.Found).Select(r => r.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return Rank(rows, kev, open, only, q.Limit);
    }

    /// <summary>Score and group the per-device rows. Pure, so the weighting is unit tested.</summary>
    public static IReadOnlyList<ExposureItem> Rank(IEnumerable<JsonElement> rows, IReadOnlySet<string> kev, IReadOnlySet<string> openIncidentDevices, IReadOnlySet<string>? only, int limit)
    {
        bool InOpen(string? id, string? name) =>
            (id is not null && openIncidentDevices.Contains(id)) || (name is not null && (openIncidentDevices.Contains(name) || openIncidentDevices.Contains(name.Split('.')[0])));

        return rows
            .Where(r => J.Str(r, "CveId") is { } c && (only is null || only.Contains(c)))
            .GroupBy(r => J.Str(r, "CveId")!.ToUpperInvariant())
            .Select(g =>
            {
                var first = g.First();
                var devices = g.GroupBy(r => J.Str(r, "DeviceId") ?? J.Str(r, "DeviceName") ?? "").Select(d => d.First()).Select(r => new ExposureDevice(
                    J.Str(r, "DeviceId"), J.Str(r, "DeviceName"), J.Str(r, "AadDeviceId"), Bool(r, "IsInternetFacing"), J.Str(r, "AssetValue"),
                    InOpen(J.Str(r, "DeviceId"), J.Str(r, "DeviceName")))).ToList();
                var severity = J.Str(first, "Severity") ?? "Medium";
                var cvss = Num(first, "CvssScore");
                var exploit = Bool(first, "IsExploitAvailable");
                var known = kev.Contains(g.Key);
                var internet = devices.Count(d => d.InternetFacing);
                var critical = devices.Count(d => d.AssetValue == "High");
                var inOpen = devices.Count(d => d.InOpenIncident);
                var (score, reasons) = Score(severity, cvss, exploit, known, devices.Count, internet, critical, inOpen);
                return new ExposureItem(g.Key, $"{g.Key} in {J.Str(first, "Software")?.Trim() ?? "installed software"}", g.Key, severity, cvss, exploit, known, devices.Count,
                    internet, critical, inOpen, score, reasons,
                    [.. devices.OrderByDescending(d => d.InOpenIncident).ThenByDescending(d => d.InternetFacing).ThenByDescending(d => d.AssetValue == "High").Take(10)],
                    J.Str(first, "Remediation"));
            })
            .OrderByDescending(x => x.Score).ThenByDescending(x => x.Devices).ThenBy(x => x.Id, StringComparer.Ordinal)
            .Take(limit).ToList();
    }

    /// <summary>
    /// 0-100. Base from severity (or CVSS when given), plus exploitability, CISA KEV, internet exposure, asset value and
    /// active incidents, with a small boost for breadth. Weights favour "being attacked now" over "many devices".
    /// </summary>
    public static (double Score, string[] Reasons) Score(string severity, double? cvss, bool exploit, bool kev, int devices, int internet, int critical, int inOpenIncidents)
    {
        var reasons = new List<string>();
        var basis = cvss is { } c ? c * 3 : severity switch { "Critical" => 28, "High" => 22, "Medium" => 14, _ => 6 };
        reasons.Add(cvss is { } cv ? $"CVSS {cv:0.0}" : $"{severity} severity");
        double s = basis;
        if (kev) { s += 25; reasons.Add("known exploited (CISA KEV)"); }
        else if (exploit) { s += 15; reasons.Add("public exploit available"); }
        if (inOpenIncidents > 0) { s += 20; reasons.Add($"{inOpenIncidents} device(s) in open incidents"); }
        if (internet > 0) { s += 12; reasons.Add($"{internet} internet-facing device(s)"); }
        if (critical > 0) { s += 8; reasons.Add($"{critical} high-value device(s)"); }
        s += Math.Min(5, Math.Log2(1 + devices));
        return (Math.Round(Math.Min(100, s), 1), [.. reasons]);
    }

    private static bool Bool(JsonElement e, string k) =>
        e.TryGetProperty(k, out var v) && (v.ValueKind == JsonValueKind.True || (v.ValueKind == JsonValueKind.String && bool.TryParse(v.GetString(), out var b) && b));

    private static double? Num(JsonElement e, string k) =>
        e.TryGetProperty(k, out var v) ? v.ValueKind switch
        {
            JsonValueKind.Number => v.GetDouble(),
            JsonValueKind.String when double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) => d,
            _ => null,
        } : null;

    private static int Int(JsonElement e, string k) => (int)(Num(e, k) ?? 0);
}
