using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Graph;

/// <summary>
/// Read-only enrichment brokered by the board so agents need no Microsoft credentials. Every call is
/// audited. Advanced hunting and Sentinel Log Analytics queries are read-only by design (KQL can't write).
/// </summary>
public sealed partial class Enrichment(Db db, Audit audit, BoardService board, MsClient ms, RateLimiter? limiter = null, Settings? settings = null)
{
    [GeneratedRegex(@"(?:^|;)\s*\.", RegexOptions.Multiline)] private static partial Regex MgmtCommand();
    [GeneratedRegex(@"\b(externaldata|http_request|http_request_post|sql_request|cosmosdb_sql_request|mysql_request|postgresql_request|azure_digital_twins_query_request|python|r)\s*\(", RegexOptions.IgnoreCase)] private static partial Regex OutboundPluginCall();
    [GeneratedRegex(@"\b(externaldata|http_request|http_request_post|sql_request|cosmosdb_sql_request|mysql_request|postgresql_request|azure_digital_twins_query_request)\b", RegexOptions.IgnoreCase)] private static partial Regex OutboundPlugin();
    [GeneratedRegex(@"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$")] private static partial Regex IsoDuration();
    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.IgnoreCase)] private static partial Regex MdeId();
    [GeneratedRegex(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase)] private static partial Regex GuidId();
    [GeneratedRegex(@"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[^\s/\\?#@]+@[^\s/\\?#@]+\.[^\s/\\?#@]+)$", RegexOptions.IgnoreCase)] private static partial Regex UserOrGuid();

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
        var span = ValidateKql(query, timespan);
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
    /// Read-only KQL directly against the configured Microsoft Sentinel Log Analytics workspace (AuditLogs, SigninLogs,
    /// AzureActivity, OfficeActivity, SecurityIncident, Watchlist, BlueboardAudit_CL). Needs SENTINEL_WORKSPACE_ID and
    /// Log Analytics Reader on the workspace for the board's managed identity.
    /// </summary>
    public async Task<object> SentinelQueryAsync(Principal p, string query, string? timespan, CancellationToken ct = default)
    {
        p.Require(Roles.Hunter);
        if (limiter is not null) await limiter.TakeAsync(p, "hunt", ct);
        var span = ValidateKql(query, timespan);
        var ws = settings?.Ti.SentinelWorkspaceId;
        if (ws is null || !Guid.TryParse(ws, out var wsId))
            throw new BoardException("SENTINEL_WORKSPACE_ID is not configured on this board (set it to the Log Analytics workspace id GUID)", 400);
        await audit.WriteAsync(p.Id, "enrich.sentinel_hunt", wsId.ToString(), new { query, timespan = span }, ct);
        var res = await ms.SendAsync(MsApi.LogAnalytics, $"/v1/workspaces/{wsId}/query", HttpMethod.Post, new { query, timespan = span }, ct);
        return ShapeLogAnalyticsResult(res);
    }

    internal static object ShapeLogAnalyticsResult(JsonElement? res)
    {
        if (res is not { } r || !r.TryGetProperty("tables", out var tables) || tables.ValueKind != JsonValueKind.Array || tables.GetArrayLength() == 0)
            return new { columns = Array.Empty<object>(), rows = Array.Empty<object>(), truncated = false, total = 0 };
        var primary = tables[0];
        var cols = primary.TryGetProperty("columns", out var c) && c.ValueKind == JsonValueKind.Array
            ? c.EnumerateArray().Select(x => new { name = Str(x, "name") ?? "", type = Str(x, "type") ?? "string" }).ToList()
            : [];
        var rawRows = primary.TryGetProperty("rows", out var rr) && rr.ValueKind == JsonValueKind.Array
            ? rr.EnumerateArray().ToList()
            : [];
        var shaped = new List<Dictionary<string, JsonElement?>>(Math.Min(rawRows.Count, 200));
        foreach (var row in rawRows.Take(200))
        {
            var dict = new Dictionary<string, JsonElement?>(cols.Count);
            if (row.ValueKind == JsonValueKind.Array)
            {
                var i = 0;
                foreach (var cell in row.EnumerateArray())
                {
                    if (i < cols.Count) dict[cols[i].name] = cell.ValueKind == JsonValueKind.Null ? null : cell.Clone();
                    i++;
                }
            }
            shaped.Add(dict);
        }
        return new
        {
            columns = cols,
            rows = shaped,
            truncated = rawRows.Count > 200,
            total = rawRows.Count,
        };
    }

    internal static string ValidateKql(string query, string? timespan)
    {
        if (query is not { Length: >= 5 and <= 10000 }) throw new BoardException("query must be 5–10000 characters");
        var span = timespan ?? "P7D";
        var dm = IsoDuration().Match(span);
        if (!dm.Success || span.EndsWith('T') || !(dm.Groups[1].Success || dm.Groups[2].Success || dm.Groups[3].Success))
            throw new BoardException("timespan must be an ISO-8601 duration, e.g. P7D or PT12H");
        if (!TryMinutes(dm.Groups[1].Value, 1440, out var dMin)
            || !TryMinutes(dm.Groups[2].Value, 60, out var hMin)
            || !TryMinutes(dm.Groups[3].Value, 1, out var mMin)
            || checked(dMin + hMin + mMin) is <= 0 or > 90L * 1440L)
            throw new BoardException("timespan must be between PT1M and P90D");

        // Strip strings and comments lexically so neither /* ... */ nor // can cloak .management or externaldata/http_request.
        var stripped = StripCommentsAndStrings(query, out var unclosedComment);
        if (unclosedComment) throw new BoardException("unclosed comment in KQL query");
        if (MgmtCommand().IsMatch(stripped)) throw new BoardException("management commands are not allowed");
        if (OutboundPlugin().IsMatch(stripped) || OutboundPluginCall().IsMatch(stripped))
            throw new BoardException("external data and outbound network plugins are not allowed in hunting queries");
        return span;
    }

    private static bool TryMinutes(string raw, long factor, out long minutes)
    {
        minutes = 0;
        if (raw.Length == 0) return true;
        if (!long.TryParse(raw, out var val) || val > 90L * 1440L) return false;
        minutes = val * factor;
        return true;
    }

    private static string StripCommentsAndStrings(string query, out bool unclosedComment)
    {
        unclosedComment = false;
        var sb = new System.Text.StringBuilder(query.Length);
        var i = 0;
        while (i < query.Length)
        {
            var c = query[i];
            var next = i + 1 < query.Length ? query[i + 1] : '\0';
            // Multi-line KQL string literals: ```...``` or ~~~...~~~
            if ((c == '`' && i + 2 < query.Length && query[i + 1] == '`' && query[i + 2] == '`')
                || (c == '~' && i + 2 < query.Length && query[i + 1] == '~' && query[i + 2] == '~'))
            {
                var fence = query.Substring(i, 3);
                sb.Append("\"\"");
                i += 3;
                var end = query.IndexOf(fence, i, StringComparison.Ordinal);
                if (end < 0) break;
                i = end + 3;
                continue;
            }
            // Verbatim strings: @"...", @'...', h@"...", H@"..."
            if ((c == '@' && (next == '"' || next == '\''))
                || ((c is 'h' or 'H') && i + 2 < query.Length && query[i + 1] == '@' && (query[i + 2] == '"' || query[i + 2] == '\'')))
            {
                var qIdx = c == '@' ? i + 1 : i + 2;
                var quote = query[qIdx];
                sb.Append("\"\"");
                i = qIdx + 1;
                while (i < query.Length)
                {
                    if (query[i] == quote)
                    {
                        if (i + 1 < query.Length && query[i + 1] == quote) { i += 2; continue; }
                        i++;
                        break;
                    }
                    i++;
                }
                continue;
            }
            // Regular quoted string literals
            if (c is '"' or '\'')
            {
                var quote = c;
                sb.Append("\"\"");
                i++;
                while (i < query.Length)
                {
                    if (query[i] == '\\') { i += 2; continue; }
                    if (query[i] == quote) { i++; break; }
                    i++;
                }
                continue;
            }
            // Line comment //
            if (c == '/' && next == '/')
            {
                sb.Append(' ');
                i += 2;
                while (i < query.Length && query[i] != '\n') i++;
                continue;
            }
            // Block comment /* ... */
            if (c == '/' && next == '*')
            {
                sb.Append(' ');
                var end = query.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (end < 0)
                {
                    unclosedComment = true;
                    break;
                }
                i = end + 2;
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
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
        if (value is not { Length: >= 1 and <= 2048 } || value.Any(char.IsControl) || value is "." or "..")
            throw new BoardException("invalid value");
        // URLs naturally contain /, ? and #: parse the host safely in the url case below. All other entity kinds
        // interpolate into Graph/MDE path segments and must never contain path or query delimiters.
        if (kind != "url" && value.IndexOfAny(['/', '\\', '?', '#']) >= 0)
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
                if (!UserOrGuid().IsMatch(value)) throw new BoardException("user must be an Entra user UPN or object id (GUID)");
                var user = await Try(MsApi.Graph, $"/v1.0/users/{e}?$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,officeLocation,createdDateTime,userType,onPremisesSyncEnabled,signInActivity")
                           ?? await ms.SendAsync(MsApi.Graph, $"/v1.0/users/{e}?$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,userType", ct: ct);
                var uid = user?.GetProperty("id").GetString();
                var roles = await Try(MsApi.Graph, $"/v1.0/users/{e}/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName");
                var risky = uid is null ? null : await Try(MsApi.Graph, $"/v1.0/identityProtection/riskyUsers/{uid}");
                var detections = uid is null || !GuidId().IsMatch(uid) ? null
                    : await Try(MsApi.Graph, $"/v1.0/identityProtection/riskDetections?$filter={Uri.EscapeDataString($"userId eq '{uid}'")}&$top=10");
                return new
                {
                    user,
                    directory_roles = roles?.GetProperty("value").EnumerateArray().Select(r => r.GetProperty("displayName").GetString()).ToList(),
                    risk = risky is { } rk ? new { level = Str(rk, "riskLevel"), state = Str(rk, "riskState"), detail = Str(rk, "riskDetail") } : null,
                    recent_risk_detections = detections is { } dt && dt.TryGetProperty("value", out var dv) && dv.ValueKind == JsonValueKind.Array
                        ? dv.EnumerateArray().Take(10).Select(d => new
                        {
                            risk_event_type = Str(d, "riskEventType"), risk_level = Str(d, "riskLevel"),
                            ip_address = Str(d, "ipAddress"), detected_at = Str(d, "detectedDateTime"),
                        }).ToList()
                        : null,
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
                var mid = mc.GetProperty("id").GetString()!;
                if (!MdeId().IsMatch(mid)) throw new BoardException("invalid device id from Defender");
                var pick = new JsonObject();
                foreach (var k in new[] { "id", "computerDnsName", "osPlatform", "osVersion", "healthStatus", "riskScore", "exposureLevel", "isolationState", "lastSeen", "lastIpAddress", "machineTags", "onboardingStatus" })
                    if (mc.TryGetProperty(k, out var v)) pick[k] = JsonNode.Parse(v.GetRawText());
                var users = await Try(MsApi.Defender, $"/api/machines/{mid}/logonusers");
                var alerts = await Try(MsApi.Defender, $"/api/machines/{mid}/alerts");
                return new
                {
                    device = pick,
                    recent_logon_users = users?.GetProperty("value").EnumerateArray().Take(10).Select(u => new
                    {
                        account_name = Str(u, "accountName"), domain = Str(u, "accountDomain"),
                        is_domain_admin = u.TryGetProperty("isDomainAdmin", out var da) && da.ValueKind == JsonValueKind.True,
                        last_seen = Str(u, "lastSeen"),
                    }).ToList(),
                    recent_alerts = alerts is { } al && al.TryGetProperty("value", out var av) && av.ValueKind == JsonValueKind.Array
                        ? av.EnumerateArray().Take(10).Select(a => new
                        {
                            id = Str(a, "id"), title = Str(a, "title"), severity = Str(a, "severity"), status = Str(a, "status"),
                            category = Str(a, "category"), created_at = Str(a, "alertCreationTime"),
                        }).ToList()
                        : null,
                };
            }
            case "ip":
            {
                var ip = Intel.Indicators.Normalise("ip", value) ?? throw new BoardException("invalid ip address");
                var ipEnc = Uri.EscapeDataString(ip);
                var stats = await Try(MsApi.Defender, $"/api/ips/{ipEnc}/stats?lookBackHours=720");
                var alerts = await Try(MsApi.Defender, $"/api/ips/{ipEnc}/alerts");
                return new
                {
                    stats,
                    related_alerts = alerts?.GetProperty("value").EnumerateArray().Take(10)
                        .Select(a => new { id = Str(a, "id"), title = Str(a, "title"), severity = Str(a, "severity"), status = Str(a, "status") }).ToList(),
                };
            }
            case "file":
            {
                var hash = Intel.Indicators.Normalise("sha256", value)
                           ?? Intel.Indicators.Normalise("sha1", value)
                           ?? Intel.Indicators.Normalise("md5", value)
                           ?? throw new BoardException("file must be a valid sha256, sha1 or md5 hash");
                var hashEnc = Uri.EscapeDataString(hash);
                return new { file = await Try(MsApi.Defender, $"/api/files/{hashEnc}"), stats = await Try(MsApi.Defender, $"/api/files/{hashEnc}/stats?lookBackHours=720") };
            }
            case "url":
            {
                var raw = value.Trim();
                if (!Uri.TryCreate(raw.Contains("://") ? raw : $"https://{raw}", UriKind.Absolute, out var u)
                    || u.Scheme is not ("http" or "https") || string.IsNullOrEmpty(u.IdnHost))
                    throw new BoardException("invalid url");
                var host = u.IdnHost.ToLowerInvariant().TrimEnd('.');
                return new { domain = host, stats = await Try(MsApi.Defender, $"/api/domains/{Uri.EscapeDataString(host)}/stats?lookBackHours=720") };
            }
            case "service_principal":
            case "oauth_app":
            {
                JsonElement? sp = null;
                if (GuidId().IsMatch(value))
                {
                    sp = await Try(MsApi.Graph, $"/v1.0/servicePrincipals/{value}?$select=id,appId,displayName,accountEnabled,servicePrincipalType,verifiedPublisher,createdDateTime,homepage,replyUrls")
                         ?? await FindSpByAppIdAsync(Try, value);
                }
                else
                {
                    var filter = Uri.EscapeDataString($"displayName eq '{value.Replace("'", "''")}'");
                    var list = await Try(MsApi.Graph, $"/v1.0/servicePrincipals?$filter={filter}&$top=1&$select=id,appId,displayName,accountEnabled,servicePrincipalType,verifiedPublisher,createdDateTime,homepage,replyUrls");
                    sp = list is { } l && l.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Array && v.GetArrayLength() > 0 ? v[0].Clone() : null;
                }
                if (sp is not { } found) return new { found = false };
                var spId = Str(found, "id");
                var safeSpId = spId is not null && GuidId().IsMatch(spId) ? spId : null;
                var grants = safeSpId is null ? null : await Try(MsApi.Graph, $"/v1.0/servicePrincipals/{safeSpId}/oauth2PermissionGrants?$top=20");
                var roles = safeSpId is null ? null : await Try(MsApi.Graph, $"/v1.0/servicePrincipals/{safeSpId}/appRoleAssignments?$top=20");
                return new
                {
                    service_principal = found,
                    oauth_grants = grants is { } g && g.TryGetProperty("value", out var gv) && gv.ValueKind == JsonValueKind.Array
                        ? gv.EnumerateArray().Take(20).Select(x => new
                        {
                            id = Str(x, "id"), consent_type = Str(x, "consentType"), principal_id = Str(x, "principalId"),
                            resource_id = Str(x, "resourceId"), scope = Str(x, "scope"),
                        }).ToList()
                        : null,
                    app_role_assignments = roles is { } r && r.TryGetProperty("value", out var rv) && rv.ValueKind == JsonValueKind.Array
                        ? rv.EnumerateArray().Take(20).Select(x => new
                        {
                            id = Str(x, "id"), resource_display_name = Str(x, "resourceDisplayName"), app_role_id = Str(x, "appRoleId"),
                        }).ToList()
                        : null,
                };
            }
            default:
                throw new BoardException("kind must be user, device, ip, file, url, service_principal or oauth_app");
        }
    }

    /// <summary>
    /// Read-only Microsoft Purview data security context for a user: recent Purview DLP and Insider Risk alerts from
    /// Microsoft Graph Security (uses existing SecurityAlert.Read.All) plus tenant sensitivity labels when granted.
    /// </summary>
    public async Task<object> LookupPurviewAsync(Principal p, string user, bool includeLabels = true, CancellationToken ct = default)
    {
        p.Require(Roles.Hunter);
        if (limiter is not null) await limiter.TakeAsync(p, "lookup", ct);
        user = user?.Trim() ?? "";
        if (user.Length is < 3 or > 320 || user.Any(char.IsControl) || user.IndexOfAny(['/', '\\', '?', '#']) >= 0 || !UserOrGuid().IsMatch(user))
            throw new BoardException("user must be an Entra user UPN or object id (GUID)");

        await audit.WriteAsync(p.Id, "enrich.purview_lookup", user, new { include_labels = includeLabels }, ct);

        async Task<JsonElement?> Try(MsApi api, string path)
        {
            try { return await ms.SendAsync(api, path, ct: ct); }
            catch (BoardException) { return null; }
        }

        var encodedUser = Uri.EscapeDataString(user);
        var userInfo = await Try(MsApi.Graph, $"/v1.0/users/{encodedUser}?$select=id,displayName,userPrincipalName,department,jobTitle");
        var oid = userInfo is { } u ? Str(u, "id") : null;
        var upn = userInfo is { } uu ? Str(uu, "userPrincipalName") : null;
        var needles = new[] { user, oid, upn }.OfType<string>().Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        var alertsRes = await Try(MsApi.Graph, "/v1.0/security/alerts_v2?$filter=serviceSource%20eq%20%27microsoftDataLossPrevention%27%20or%20serviceSource%20eq%20%27microsoftInsiderRiskManagement%27&$top=50")
                        ?? await Try(MsApi.Graph, "/v1.0/security/alerts_v2?$top=50");

        var matchedAlerts = new List<object>();
        if (alertsRes is { } ar && ar.TryGetProperty("value", out var av) && av.ValueKind == JsonValueKind.Array)
        {
            foreach (var alert in av.EnumerateArray())
            {
                var src = Str(alert, "serviceSource") ?? Str(alert, "detectionSource") ?? "";
                if (!src.Contains("DataLossPrevention", StringComparison.OrdinalIgnoreCase)
                    && !src.Contains("InsiderRisk", StringComparison.OrdinalIgnoreCase)
                    && !src.Contains("Purview", StringComparison.OrdinalIgnoreCase)
                    && !src.Contains("InformationProtection", StringComparison.OrdinalIgnoreCase))
                    continue;
                var raw = alert.GetRawText();
                if (!needles.Any(n => raw.Contains(n, StringComparison.OrdinalIgnoreCase))) continue;
                var desc = Str(alert, "description");
                matchedAlerts.Add(new
                {
                    id = Str(alert, "id"),
                    title = Str(alert, "title"),
                    severity = Str(alert, "severity"),
                    status = Str(alert, "status"),
                    service_source = src,
                    category = Str(alert, "category"),
                    created_at = Str(alert, "createdDateTime"),
                    description = desc is { Length: > 500 } ? desc[..500] : desc,
                });
                if (matchedAlerts.Count >= 20) break;
            }
        }

        List<object>? labels = null;
        var labelsStatus = "skipped";
        if (includeLabels)
        {
            var labelsRes = await Try(MsApi.Graph, "/v1.0/security/dataSecurityAndGovernance/sensitivityLabels?$select=id,name,description,sensitivity,isActive");
            if (labelsRes is { } lr && lr.TryGetProperty("value", out var lv) && lv.ValueKind == JsonValueKind.Array)
            {
                labelsStatus = "ok";
                labels = lv.EnumerateArray().Take(50).Select(l => (object)new
                {
                    id = Str(l, "id"),
                    name = Str(l, "name"),
                    description = Str(l, "description"),
                    sensitivity = l.TryGetProperty("sensitivity", out var sv) && sv.ValueKind == JsonValueKind.Number ? (int?)sv.GetInt32() : null,
                    is_active = !l.TryGetProperty("isActive", out var act) || act.ValueKind != JsonValueKind.False,
                }).ToList();
            }
            else
            {
                labelsStatus = "not_granted_or_unavailable";
            }
        }

        return new
        {
            user = userInfo,
            queried = user,
            alert_count = matchedAlerts.Count,
            dlp_and_insider_alerts = matchedAlerts,
            sensitivity_labels = labels,
            labels_status = labelsStatus,
        };
    }

    private static async Task<JsonElement?> FindSpByAppIdAsync(Func<MsApi, string, Task<JsonElement?>> tryGet, string appId)
    {
        var filter = Uri.EscapeDataString($"appId eq '{appId}'");
        var list = await tryGet(MsApi.Graph, $"/v1.0/servicePrincipals?$filter={filter}&$top=1&$select=id,appId,displayName,accountEnabled,servicePrincipalType,verifiedPublisher,createdDateTime,homepage,replyUrls");
        return list is { } l && l.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Array && v.GetArrayLength() > 0 ? v[0].Clone() : null;
    }

    private static string? Str(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
