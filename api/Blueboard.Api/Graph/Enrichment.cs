using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Graph;

/// <summary>
/// Read-only enrichment brokered by the board so agents need no Microsoft credentials. Every call is
/// audited. Advanced hunting is read-only by design (KQL can't write).
/// </summary>
public sealed partial class Enrichment(Db db, Audit audit, BoardService board, MsClient ms, RateLimiter? limiter = null)
{
    [GeneratedRegex(@"^\s*\.", RegexOptions.Multiline)] private static partial Regex MgmtCommand();
    [GeneratedRegex(@"//.*$", RegexOptions.Multiline)] private static partial Regex KqlComment();
    [GeneratedRegex(@"^P(T?\d+[DHM])+$")] private static partial Regex IsoDuration();
    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.IgnoreCase)] private static partial Regex MdeId();

    public async Task<JsonObject> GetIncidentAsync(string reference, CancellationToken ct = default)
    {
        var id = await board.ResolveIncidentAsync(reference, ct) ?? throw BoardException.NotFound("incident");
        await using var cmd = db.Command("""
            select id, graph_id, display_name, severity, status, classification, determination, assigned_to, web_url, data::text
            from incidents where id = @id
            """).With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) throw BoardException.NotFound("incident");
        var data = JsonDocument.Parse(r.GetString(9)).RootElement.Clone();
        var alerts = new JsonArray();
        if (data.TryGetProperty("alerts", out var list) && list.ValueKind == JsonValueKind.Array)
            foreach (var a in list.EnumerateArray())
            {
                var o = new JsonObject();
                foreach (var k in new[] { "id", "title", "severity", "category", "serviceSource", "detectionSource", "firstActivityDateTime", "lastActivityDateTime" })
                    if (a.TryGetProperty(k, out var v)) o[k] = JsonNode.Parse(v.GetRawText());
                if (a.TryGetProperty("mitreTechniques", out var mt)) o["mitreTechniques"] = JsonNode.Parse(mt.GetRawText());
                if (a.TryGetProperty("description", out var d) && d.ValueKind == JsonValueKind.String)
                    o["description"] = d.GetString() is { Length: > 2000 } long_ ? long_[..2000] : d.GetString();
                alerts.Add(o);
            }
        return new JsonObject
        {
            ["id"] = r.GetGuid(0).ToString(),
            ["graph_id"] = r.GetString(1),
            ["display_name"] = r.GetString(2),
            ["severity"] = r.GetString(3),
            ["status"] = r.GetString(4),
            ["classification"] = r.Get<string>("classification"),
            ["determination"] = r.Get<string>("determination"),
            ["assigned_to"] = r.Get<string>("assigned_to"),
            ["web_url"] = r.Get<string>("web_url"),
            ["alerts"] = alerts,
            ["entities"] = JsonSerializer.SerializeToNode(Entities.Extract(data), Json.Options),
        };
    }

    public async Task<object> HuntAsync(Principal p, string query, string? timespan, CancellationToken ct = default)
    {
        p.Require(Roles.Hunter);
        // Before any Graph call: advanced hunting has tenant-wide quotas that one noisy agent must not burn (issue #5).
        if (limiter is not null) await limiter.TakeAsync(p, "hunt", ct);
        if (query is not { Length: >= 5 and <= 10000 }) throw new BoardException("query must be 5–10000 characters");
        var span = timespan ?? "P7D";
        if (!IsoDuration().IsMatch(span)) throw new BoardException("timespan must be an ISO-8601 duration, e.g. P7D or PT12H");
        // Advanced hunting is read-only, but refuse management commands outright.
        if (MgmtCommand().IsMatch(KqlComment().Replace(query, ""))) throw new BoardException("management commands are not allowed");
        await audit.WriteAsync(p.Id, "enrich.hunt", null, new { query, timespan = span }, ct);
        var res = await ms.SendAsync(MsApi.Graph, "/v1.0/security/runHuntingQuery", HttpMethod.Post, new { query, timespan = span }, ct);
        var results = res?.GetProperty("results").EnumerateArray().ToList() ?? [];
        return new
        {
            columns = res?.GetProperty("schema"),
            rows = results.Take(200).ToList(),
            truncated = results.Count > 200,
            total = results.Count,
        };
    }

    /// <summary>
    /// Board-built KQL (threat intel and exposure checks): the query comes from a builder that only accepts validated
    /// values, never from a caller. Audited like every hunt; actor is null when the board runs it on a schedule.
    /// </summary>
    internal async Task<IReadOnlyList<JsonElement>> RunBoardQueryAsync(Guid? actorId, string evt, string query, string timespan, object? detail, CancellationToken ct = default)
    {
        await audit.WriteAsync(actorId, evt, null, new { query, timespan, detail }, ct);
        var res = await ms.SendAsync(MsApi.Graph, "/v1.0/security/runHuntingQuery", HttpMethod.Post, new { query, timespan }, ct);
        return res is { } r && r.TryGetProperty("results", out var rows) && rows.ValueKind == JsonValueKind.Array
            ? rows.EnumerateArray().Select(x => x.Clone()).ToList()
            : [];
    }

    public async Task<object> LookupAsync(Principal p, string kind, string value, CancellationToken ct = default)
    {
        p.Require(Roles.Hunter);
        if (limiter is not null) await limiter.TakeAsync(p, "lookup", ct);
        if (value is not { Length: >= 1 and <= 2048 } || value.IndexOfAny(['/', '\\', '?', '#']) >= 0 || value is "." or "..")
            throw new BoardException("invalid value");
        await audit.WriteAsync(p.Id, "enrich.lookup", $"{kind}:{value}", null, ct);
        var e = Uri.EscapeDataString(value);

        async Task<JsonElement?> Try(MsApi api, string path)
        {
            try { return await ms.SendAsync(api, path, ct: ct); }
            catch (BoardException) { return null; }
        }

        switch (kind)
        {
            case "user":
            {
                var user = await Try(MsApi.Graph, $"/v1.0/users/{e}?$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,officeLocation,createdDateTime,userType,onPremisesSyncEnabled,signInActivity")
                           ?? await ms.SendAsync(MsApi.Graph, $"/v1.0/users/{e}?$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,userType", ct: ct);
                var uid = user?.GetProperty("id").GetString();
                var roles = await Try(MsApi.Graph, $"/v1.0/users/{e}/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName");
                var risky = uid is null ? null : await Try(MsApi.Graph, $"/v1.0/identityProtection/riskyUsers/{uid}");
                return new
                {
                    user,
                    directory_roles = roles?.GetProperty("value").EnumerateArray().Select(r => r.GetProperty("displayName").GetString()).ToList(),
                    risk = risky is { } rk ? new { level = Str(rk, "riskLevel"), state = Str(rk, "riskState"), detail = Str(rk, "riskDetail") } : null,
                };
            }
            case "device":
            {
                JsonElement? machine;
                if (MdeId().IsMatch(value)) machine = await ms.SendAsync(MsApi.Defender, $"/api/machines/{value}", ct: ct);
                else
                {
                    var filter = Uri.EscapeDataString($"computerDnsName eq '{value.Replace("'", "''")}'");
                    var list = await ms.SendAsync(MsApi.Defender, $"/api/machines?$filter={filter}", ct: ct);
                    machine = list?.GetProperty("value").EnumerateArray().FirstOrDefault() is { ValueKind: JsonValueKind.Object } m ? m : null;
                }
                if (machine is not { } mc) return new { found = false };
                var pick = new JsonObject();
                foreach (var k in new[] { "id", "computerDnsName", "osPlatform", "osVersion", "healthStatus", "riskScore", "exposureLevel", "isolationState", "lastSeen", "lastIpAddress", "machineTags", "onboardingStatus" })
                    if (mc.TryGetProperty(k, out var v)) pick[k] = JsonNode.Parse(v.GetRawText());
                var users = await Try(MsApi.Defender, $"/api/machines/{mc.GetProperty("id").GetString()}/logonusers");
                return new
                {
                    device = pick,
                    recent_logon_users = users?.GetProperty("value").EnumerateArray().Take(10).Select(u => new
                    {
                        account_name = Str(u, "accountName"), domain = Str(u, "accountDomain"),
                        is_domain_admin = u.TryGetProperty("isDomainAdmin", out var da) && da.ValueKind == JsonValueKind.True,
                        last_seen = Str(u, "lastSeen"),
                    }).ToList(),
                };
            }
            case "ip":
            {
                var stats = await Try(MsApi.Defender, $"/api/ips/{e}/stats?lookBackHours=720");
                var alerts = await Try(MsApi.Defender, $"/api/ips/{e}/alerts");
                return new
                {
                    stats,
                    related_alerts = alerts?.GetProperty("value").EnumerateArray().Take(10)
                        .Select(a => new { id = Str(a, "id"), title = Str(a, "title"), severity = Str(a, "severity"), status = Str(a, "status") }).ToList(),
                };
            }
            case "file":
                return new { file = await Try(MsApi.Defender, $"/api/files/{e}"), stats = await Try(MsApi.Defender, $"/api/files/{e}/stats?lookBackHours=720") };
            case "url":
            {
                if (!Uri.TryCreate(value.Contains("://") ? value : $"https://{value}", UriKind.Absolute, out var u)) throw new BoardException("invalid url");
                return new { domain = u.Host, stats = await Try(MsApi.Defender, $"/api/domains/{Uri.EscapeDataString(u.Host)}/stats?lookBackHours=720") };
            }
            default:
                throw new BoardException("kind must be user, device, ip, file or url");
        }
    }

    private static string? Str(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
