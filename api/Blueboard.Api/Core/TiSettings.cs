namespace Blueboard.Api.Core;

/// <summary>
/// Threat intel settings. Every source is off unless its TI_*_ENABLED flag is "true". Read once at startup.
/// See docs/THREAT_INTEL.md and docs/ti/sources.md.
/// </summary>
public sealed record TiSettings
{
    public bool PwnWatch { get; init; }
    public bool Kev { get; init; }
    public bool Epss { get; init; }
    public bool Nvd { get; init; }
    public bool Osv { get; init; }
    /// <summary>Microsoft Sentinel threat intelligence (ThreatIntelIndicators via advanced hunting).</summary>
    public bool Sentinel { get; init; }
    /// <summary>Microsoft Threat Intelligence in Graph. Needs ThreatIntelligence.Read.All (grant with TI_MSTI=1).</summary>
    public bool Msti { get; init; }
    /// <summary>"Are we exposed?" checks against Defender Vulnerability Management.</summary>
    public bool Exposure { get; init; }
    /// <summary>kql (advanced hunting, no extra permission) or api (MDE vulnerabilities API, needs Vulnerability.Read.All).</summary>
    public string ExposureSource { get; init; } = "kql";
    /// <summary>Optional: raises the NVD rate limit from 5 to 50 requests per rolling 30 seconds.</summary>
    public string? NvdApiKey { get; init; }
    public long MaxResponseBytes { get; init; } = 25 * 1024 * 1024;
    /// <summary>Local demo only: serve every source from recorded fixtures instead of the network. Refused in Azure.</summary>
    public string? FixturesDir { get; init; }
    /// <summary>Log Analytics workspace id (GUID) that publish_ti_indicator uploads STIX objects to.</summary>
    public string? SentinelWorkspaceId { get; init; }
    /// <summary>
    /// ARM resource id of the Sentinel workspace (/subscriptions/…/resourceGroups/…/providers/Microsoft.OperationalInsights/workspaces/…),
    /// for create_detection_rule / disable_detection_rule with target sentinel.
    /// </summary>
    public string? SentinelWorkspaceResourceId { get; init; }
    /// <summary>Public URL of the web app, used for links back to the board in published indicators.</summary>
    public string? BoardWebUrl { get; init; }

    public bool AnyEnabled => PwnWatch || Kev || Epss || Nvd || Osv || Sentinel || Msti || Exposure;

    public const string CveWatchRefused = "cve.watch is unavailable, see docs/ti/sources.md";

    public static TiSettings From(Func<string, string?> env, bool inAzure)
    {
        bool Flag(string k) => env(k) is "true" or "1" or "True";
        // Reserved so nobody turns on a dead source by mistake (issue #21).
        if (Flag("TI_CVEWATCH_ENABLED")) throw new InvalidOperationException(CveWatchRefused);
        var source = env("TI_EXPOSURE_SOURCE") ?? "kql";
        if (source is not ("kql" or "api")) throw new InvalidOperationException("TI_EXPOSURE_SOURCE must be kql or api");
        var fixtures = env("TI_FIXTURES_DIR");
        if (fixtures is not null && inAzure) throw new InvalidOperationException("TI_FIXTURES_DIR must not be set in Azure");
        return new TiSettings
        {
            PwnWatch = Flag("TI_PWNWATCH_ENABLED"),
            Kev = Flag("TI_KEV_ENABLED"),
            Epss = Flag("TI_EPSS_ENABLED"),
            Nvd = Flag("TI_NVD_ENABLED"),
            Osv = Flag("TI_OSV_ENABLED"),
            Sentinel = Flag("TI_SENTINEL_ENABLED"),
            Msti = Flag("TI_MSTI_ENABLED"),
            Exposure = Flag("TI_EXPOSURE_ENABLED"),
            ExposureSource = source,
            NvdApiKey = env("NVD_API_KEY"),
            MaxResponseBytes = long.TryParse(env("TI_MAX_RESPONSE_BYTES"), out var max) && max > 0 ? max : 25 * 1024 * 1024,
            FixturesDir = fixtures,
            SentinelWorkspaceId = env("SENTINEL_WORKSPACE_ID"),
            SentinelWorkspaceResourceId = env("SENTINEL_WORKSPACE_RESOURCE_ID"),
            BoardWebUrl = env("BOARD_WEB_URL"),
        };
    }
}
