using System.Text;
using Blueboard.Api.Core;

namespace Blueboard.Api.Intel;

/// <summary>
/// KQL the board builds itself. Only values that passed <see cref="Indicators"/> validation reach these builders;
/// each is still written as an escaped string literal, so nothing a caller types is concatenated into the query.
/// Column names checked against Microsoft's table references on 19-11-2026.
/// </summary>
public static class Kql
{
    public const int MaxValues = 100;

    /// <summary>A KQL double-quoted string literal. Control characters are refused outright.</summary>
    public static string Literal(string value)
    {
        if (value.Any(char.IsControl)) throw new BoardException("refusing control characters in a KQL value");
        var sb = new StringBuilder("\"");
        foreach (var c in value) sb.Append(c switch { '\\' => "\\\\", '"' => "\\\"", _ => c.ToString() });
        return sb.Append('"').ToString();
    }

    private static string Dynamic(IEnumerable<string> values) => $"dynamic([{string.Join(", ", values.Select(Literal))}])";

    /// <summary>CVE ids, upper case, deduplicated; refuses the whole list if any id isn't CVE-\d{4}-\d{4,}.</summary>
    public static IReadOnlyList<string> ValidCves(IEnumerable<string> ids)
    {
        var list = new List<string>();
        foreach (var id in ids)
            list.Add(Indicators.NormaliseCve(id) ?? throw new BoardException($"invalid CVE id '{(id.Length > 40 ? id[..40] : id)}'"));
        var distinct = list.Distinct().ToList();
        if (distinct.Count is 0 or > MaxValues) throw new BoardException($"give 1–{MaxValues} CVE ids");
        return distinct;
    }

    /// <summary>"Are we exposed?" over Defender Vulnerability Management (issue #18).</summary>
    public static string Exposure(IReadOnlyList<string> cves) =>
        $"""
        DeviceTvmSoftwareVulnerabilities
        | where CveId in~ ({Dynamic(ValidCves(cves))})
        | summarize Devices = dcount(DeviceId), DeviceIds = make_set(DeviceId, 500), DeviceNames = make_set(DeviceName, 20),
                    Software = make_set(strcat(SoftwareVendor, " ", SoftwareName, " ", SoftwareVersion), 10),
                    Severity = any(VulnerabilitySeverityLevel), Remediation = make_set(RecommendedSecurityUpdate, 5) by CveId
        """;

    /// <summary>Installed vendors and products, for automatic pwn.watch watches.</summary>
    public const string Inventory = """
        DeviceTvmSoftwareInventory
        | where isnotempty(SoftwareName)
        | summarize Devices = dcount(DeviceId) by SoftwareVendor, SoftwareName
        | top 300 by Devices
        """;

    /// <summary>Indicators of compromise to their STIX observable keys in ThreatIntelIndicators.</summary>
    public static string ObservableKey(string kind, string value) => kind switch
    {
        "ip" => value.Contains(':') ? "ipv6-addr:value" : "ipv4-addr:value",
        "domain" => "domain-name:value",
        "url" => "url:value",
        "sha256" => "file:hashes.'SHA-256'",
        "sha1" => "file:hashes.'SHA-1'",
        "md5" => "file:hashes.MD5",
        "email" => "email-addr:value",
        _ => throw new BoardException($"{kind} is not a Sentinel TI observable"),
    };

    /// <summary>
    /// Microsoft Sentinel threat intelligence (issue #19), via advanced hunting on a workspace connected to the
    /// Defender portal. Uses the ThreatIntelIndicators table (the legacy ThreatIntelligenceIndicator table stopped
    /// receiving data after 31 July 2025). The latest version of each indicator is taken first, then filtered.
    /// </summary>
    public static string SentinelIndicators(IReadOnlyList<IntelKey> keys)
    {
        if (keys.Count is 0 or > MaxValues) throw new BoardException($"give 1–{MaxValues} indicators");
        var values = keys.Select(k => Indicators.Normalise(k.Kind, k.Value) is { } v && k.Kind != "cve"
                ? v : throw new BoardException($"invalid {k.Kind} indicator")).Distinct().ToList();
        return $"""
            ThreatIntelIndicators
            | where ObservableValue in~ ({Dynamic(values)})
            | summarize arg_max(TimeGenerated, *) by Id
            | where IsActive == true and Revoked == false and IsDeleted == false and (isnull(ValidUntil) or ValidUntil > now())
            | extend Name = tostring(Data.name), Description = substring(tostring(Data.description), 0, 500), Labels = Data.labels
            | project Id, ObservableKey, ObservableValue, Confidence, SourceSystem, ValidUntil, Modified, Tags, Name, Description, Labels
            | take 200
            """;
    }
}
