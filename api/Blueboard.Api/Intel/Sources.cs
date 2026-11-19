using Blueboard.Api.Core;

namespace Blueboard.Api.Intel;

/// <summary>Static facts about one intel source: how to turn it on, what it answers, how to credit it.</summary>
public sealed record SourceInfo(
    string Id, string Name, string Flag, string Attribution, string[] Kinds, string Mode, string? Permission, string Home);

/// <summary>Every source the board knows about, including the ones it refuses (cve.watch).</summary>
public static class Sources
{
    public const string PwnWatch = "pwn.watch";
    public const string Kev = "cisa-kev";
    public const string Epss = "first-epss";
    public const string Nvd = "nvd";
    public const string Osv = "osv";
    public const string Sentinel = "sentinel-ti";
    public const string Msti = "microsoft-ti";
    public const string Exposure = "defender-tvm";
    public const string CveWatch = "cve.watch";

    public const string NvdNotice = "This product uses data from the NVD API but is not endorsed or certified by the NVD.";

    public static readonly SourceInfo[] All =
    [
        new(PwnWatch, "pwn.watch", "TI_PWNWATCH_ENABLED", "Source: pwn.watch", ["cve"], "feed", null, "https://pwn.watch"),
        new(Kev, "CISA KEV", "TI_KEV_ENABLED", "Source: CISA KEV", ["cve"], "feed", null, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
        new(Epss, "FIRST EPSS", "TI_EPSS_ENABLED", "Source: FIRST EPSS", ["cve"], "on demand", null, "https://www.first.org/epss/"),
        new(Nvd, "NVD", "TI_NVD_ENABLED", $"Source: NVD. {NvdNotice}", ["cve"], "on demand", null, "https://nvd.nist.gov"),
        new(Osv, "OSV.dev", "TI_OSV_ENABLED", "Source: OSV.dev (GitHub advisories via OSV, CC-BY-4.0)", ["cve", "ghsa"], "on demand", null, "https://osv.dev"),
        new(Sentinel, "Sentinel TI", "TI_SENTINEL_ENABLED", "Source: Microsoft Sentinel threat intelligence (this tenant)",
            ["ip", "domain", "url", "sha256", "sha1", "md5", "email"], "on demand", "ThreatHunting.Read.All (already granted)", "https://learn.microsoft.com/azure/sentinel/understand-threat-intelligence"),
        new(Msti, "Microsoft TI", "TI_MSTI_ENABLED", "Source: Microsoft Threat Intelligence", ["cve", "ip", "domain", "url"], "on demand",
            "ThreatIntelligence.Read.All (grant-permissions.sh with TI_MSTI=1)", "https://learn.microsoft.com/graph/api/resources/security-threatintelligence-overview"),
        new(Exposure, "Defender exposure", "TI_EXPOSURE_ENABLED", "Source: Microsoft Defender Vulnerability Management (this tenant)", ["cve"], "on demand",
            "ThreatHunting.Read.All (already granted); Vulnerability.Read.All only with TI_EXPOSURE_SOURCE=api", "https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table"),
        new(CveWatch, "cve.watch", "TI_CVEWATCH_ENABLED", "Source: cve.watch", ["cve"], "unavailable", null, "https://cve.watch"),
    ];

    public static SourceInfo Get(string id) => All.First(s => s.Id == id);

    public static bool Enabled(TiSettings ti, string id) => id switch
    {
        PwnWatch => ti.PwnWatch,
        Kev => ti.Kev,
        Epss => ti.Epss,
        Nvd => ti.Nvd,
        Osv => ti.Osv,
        Sentinel => ti.Sentinel,
        Msti => ti.Msti,
        Exposure => ti.Exposure,
        _ => false,
    };
}
