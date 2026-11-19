using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;

namespace Blueboard.Api.Intel;

/// <summary>
/// The tenant's own intel, through the board's managed identity: Sentinel TI and Defender exposure (advanced hunting),
/// Microsoft Threat Intelligence (Graph). Every value is validated before it reaches KQL or a Graph path.
/// In local demo mode (TI_FIXTURES_DIR) recorded fixtures stand in for Microsoft, since these can't be called without a tenant.
/// </summary>
public sealed class MicrosoftIntel(Enrichment enrich, MsClient ms, Settings settings)
{
    private string? Fixtures => settings.Ti.FixturesDir;

    /// <summary>One advanced hunting query built by the board. Returns the result rows.</summary>
    public async Task<IReadOnlyList<JsonElement>> HuntAsync(Guid? actor, string evt, string query, string fixture, object? detail, CancellationToken ct)
    {
        if (Fixtures is { } dir) return await FixtureRowsAsync(dir, fixture, ct);
        return await enrich.RunBoardQueryAsync(actor, evt, query, "P30D", detail, ct);
    }

    /// <summary>Graph GET under /v1.0/security/threatIntelligence/. Null when Microsoft has no record (404).</summary>
    public async Task<JsonElement?> MstiAsync(string path, string fixture, CancellationToken ct)
    {
        if (Fixtures is { } dir)
        {
            var file = Path.Combine(dir, "msti", fixture);
            return File.Exists(file) ? JsonDocument.Parse(await File.ReadAllTextAsync(file, ct)).RootElement.Clone() : null;
        }
        try
        {
            return await ms.SendAsync(MsApi.Graph, $"/v1.0/security/threatIntelligence/{path}", ct: ct);
        }
        catch (BoardException ex) when (ex.UpstreamStatus == 404)
        {
            return null;
        }
        catch (BoardException ex) when (ex.UpstreamStatus == 403)
        {
            throw new BoardException("permission ThreatIntelligence.Read.All not granted", 502) { UpstreamStatus = 403 };
        }
    }

    private static async Task<IReadOnlyList<JsonElement>> FixtureRowsAsync(string dir, string fixture, CancellationToken ct)
    {
        var file = Path.Combine(dir, fixture);
        if (!File.Exists(file)) return [];
        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(file, ct));
        return doc.RootElement.TryGetProperty("results", out var rows) && rows.ValueKind == JsonValueKind.Array
            ? rows.EnumerateArray().Select(r => r.Clone()).ToList()
            : [];
    }

    // ── result shaping (pure, unit tested) ──────────────────────────────────────────────────────

    public sealed record ExposureRow(string Cve, int Devices, string[] DeviceIds, string[] DeviceNames, string[] Software, string? Severity, string[] Remediation);

    public static IReadOnlyList<ExposureRow> ExposureRows(IEnumerable<JsonElement> rows) => rows
        .Select(r => (Cve: Indicators.NormaliseCve(J.Str(r, "CveId")), r))
        .Where(x => x.Cve is not null)
        .Select(x => new ExposureRow(x.Cve!, (int)(J.Num(x.r, "Devices") ?? 0), Strs(x.r, "DeviceIds", 500), Strs(x.r, "DeviceNames", 20),
            Strs(x.r, "Software", 10), J.Str(x.r, "Severity"), Strs(x.r, "Remediation", 5)))
        .ToList();

    public static JsonArray SentinelMatches(IEnumerable<JsonElement> rows) => new(rows.Take(50).Select(r => (JsonNode?)new JsonObject
    {
        ["id"] = J.Str(r, "Id"),
        ["observable_key"] = J.Str(r, "ObservableKey"),
        ["observable_value"] = J.Str(r, "ObservableValue"),
        ["confidence"] = J.Num(r, "Confidence"),
        ["source_system"] = J.Str(r, "SourceSystem"),
        ["valid_until"] = J.Str(r, "ValidUntil"),
        ["modified"] = J.Str(r, "Modified"),
        ["tags"] = J.Cap(J.Str(r, "Tags"), 300),
        ["name"] = J.Cap(J.Str(r, "Name"), 300),
        ["description"] = J.Cap(J.Str(r, "Description"), 500),
    }).ToArray());

    public static JsonObject MstiVulnerability(JsonElement v) => new()
    {
        ["id"] = J.Str(v, "id"),
        ["severity"] = J.Str(v, "severity"),
        ["priority_score"] = J.Num(v, "priorityScore"),
        ["active_exploits_observed"] = J.Bool(v, "activeExploitsObserved"),
        ["exploits_available"] = J.Bool(v, "exploitsAvailable"),
        ["has_chatter"] = J.Bool(v, "hasChatter"),
        ["cvss3_score"] = J.Obj(v, "cvss3Summary") is { } c3 ? J.Num(c3, "score") : null,
        ["cvss3_vector"] = J.Obj(v, "cvss3Summary") is { } c3v ? J.Str(c3v, "vectorString") : null,
        ["published"] = J.Str(v, "publishedDateTime"),
        ["last_modified"] = J.Str(v, "lastModifiedDateTime"),
        ["description"] = J.Obj(v, "description") is { } d ? J.Cap(J.Str(d, "content"), 2000) : null,
        ["remediation"] = J.Obj(v, "remediation") is { } rm ? J.Cap(J.Str(rm, "content"), 2000) : null,
    };

    public static JsonObject MstiReputation(JsonElement r) => new()
    {
        ["classification"] = J.Str(r, "classification"),
        ["score"] = J.Num(r, "score"),
        ["rules"] = new JsonArray(J.Arr(r, "rules").Take(10).Select(x => (JsonNode?)new JsonObject
        {
            ["name"] = J.Cap(J.Str(x, "name"), 200),
            ["severity"] = J.Str(x, "severity"),
            ["description"] = J.Cap(J.Str(x, "description"), 500),
        }).ToArray()),
    };

    private static string[] Strs(JsonElement r, string k, int max) => J.Strs(r, k, max).Select(s => J.Cap(s, 300)!).ToArray();
}
