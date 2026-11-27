// Mock Microsoft Graph and Defender for Endpoint API for the local demo. See Blueboard.MockMsApi.csproj.
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;

if (Environment.GetEnvironmentVariable("DEMO_MODE") != "true")
{
    Console.Error.WriteLine("mock-msapi refuses to start: set DEMO_MODE=true (local demo only)");
    return 1;
}
if (Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID") is not null || Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Production")
{
    Console.Error.WriteLine("mock-msapi refuses to start in Azure or a Production environment");
    return 1;
}

var fixtures = Environment.GetEnvironmentVariable("FIXTURES_DIR") ?? Path.Combine(AppContext.BaseDirectory, "fixtures");
var incidents = Fixtures.LoadIncidents(Path.Combine(fixtures, "incidents"));
var entities = JsonNode.Parse(File.ReadAllText(Path.Combine(fixtures, "entities.json")))!.AsObject();
var exposure = JsonNode.Parse(File.ReadAllText(Path.Combine(fixtures, "exposure.json")))!.AsObject();
var writes = new ConcurrentQueue<object>();
Console.WriteLine($"mock-msapi: {incidents.Count} incidents from {fixtures}");

var builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
var app = builder.Build();

app.MapGet("/healthz", () => Results.Text("ok"));
app.MapGet("/_writes", () => Results.Json(writes.ToArray())); // what the broker would have changed (dry run never calls these)

// ── Graph ──────────────────────────────────────────────────────────────────────────────────────
app.MapGet("/v1.0/security/incidents", () => Results.Json(new { value = Fixtures.Fresh(incidents) }));
app.MapGet("/v1.0/security/incidents/{id}", (string id) =>
    Fixtures.Fresh(incidents).FirstOrDefault(i => i["id"]!.GetValue<string>() == id) is { } inc ? Results.Json(inc) : NotFound());
app.MapPost("/v1.0/security/runHuntingQuery", async (HttpRequest req) =>
{
    var body = await JsonNode.ParseAsync(req.Body);
    var query = body?["query"]?.GetValue<string>() ?? "";
    // Board-built exposure queries and the demo's back-testable detection get canned rows (fixtures/exposure.json).
    if (Demo.HuntingRows(exposure, query) is { } canned) return Results.Json(canned);
    return Results.Json(new
    {
        schema = new[] { new { name = "Query", type = "String" }, new { name = "Matches", type = "Int64" } },
        results = new[] { new Dictionary<string, object> { ["Query"] = query.Length > 120 ? query[..120] : query, ["Matches"] = 1 } },
    });
});
app.MapGet("/v1.0/users/{id}", (string id) => Entity("users", id));
app.MapGet("/v1.0/users/{id}/transitiveMemberOf/microsoft.graph.directoryRole", (string id) => Results.Json(new { value = Array.Empty<object>() }));
app.MapGet("/v1.0/identityProtection/riskyUsers/{id}", (string id) =>
    Results.Json(new { id, riskLevel = id.EndsWith("0003") ? "medium" : "none", riskState = id.EndsWith("0003") ? "atRisk" : "none", riskDetail = "none" }));
app.MapGet("/v1.0/identityProtection/riskDetections", () => Results.Json(new { value = Array.Empty<object>() }));
app.MapGet("/v1.0/servicePrincipals/{id}", (string id) => Entity("servicePrincipals", id, new { id, appId = id, displayName = "Mock App", accountEnabled = true }));
app.MapGet("/v1.0/servicePrincipals", () => Results.Json(new { value = Array.Empty<object>() }));
app.MapGet("/v1.0/servicePrincipals/{id}/oauth2PermissionGrants", () => Results.Json(new { value = Array.Empty<object>() }));
app.MapGet("/v1.0/servicePrincipals/{id}/appRoleAssignments", () => Results.Json(new { value = Array.Empty<object>() }));
app.MapGet("/v1.0/security/alerts_v2", () => Results.Json(new
{
    value = new object[]
    {
        new
        {
            id = "purview-dlp-demo-1",
            title = "Purview DLP: Confidential Customer Export uploaded to personal cloud",
            severity = "high",
            status = "inProgress",
            serviceSource = "microsoftDataLossPrevention",
            category = "DataLossPrevention",
            createdDateTime = DateTimeOffset.UtcNow.AddMinutes(-18).ToString("O"),
            description = "DLP policy 'Australia Privacy Act PII' matched 42 records uploaded by m.chen@contoso.com.",
            evidence = new object[]
            {
                new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.userEvidence", ["userAccount"] = new { userPrincipalName = "m.chen@contoso.com", azureAdUserId = "11111111-1111-1111-1111-111111110003" } }
            },
        },
        new
        {
            id = "purview-irm-demo-1",
            title = "Insider Risk: Departing employee anomalous SharePoint & OneDrive downloads",
            severity = "medium",
            status = "new",
            serviceSource = "microsoftInsiderRiskManagement",
            category = "InsiderRisk",
            createdDateTime = DateTimeOffset.UtcNow.AddHours(-2).ToString("O"),
            description = "Sequence of bulk SharePoint downloads followed by sensitivity label downgrade for m.chen@contoso.com.",
            evidence = new object[]
            {
                new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.userEvidence", ["userAccount"] = new { userPrincipalName = "m.chen@contoso.com", azureAdUserId = "11111111-1111-1111-1111-111111110003" } }
            },
        },
    },
}));
app.MapGet("/v1.0/security/dataSecurityAndGovernance/sensitivityLabels", () => Results.Json(new
{
    value = new[]
    {
        new { id = "lbl-public", name = "Public", description = "Approved for public release", sensitivity = 0, isActive = true },
        new { id = "lbl-general", name = "General", description = "Internal business data", sensitivity = 1, isActive = true },
        new { id = "lbl-confidential", name = "Confidential", description = "Sensitive commercial or PII records", sensitivity = 2, isActive = true },
        new { id = "lbl-highly-confidential", name = "Highly Confidential - Crown Jewels", description = "Restricted board & incident evidence", sensitivity = 3, isActive = true },
    },
}));
app.MapPost("/v1.0/security/dataSecurityAndGovernance/processContent", () => Results.Json(new { policyActions = Array.Empty<object>() }));
app.MapPost("/v1/workspaces/{id}/query", async (HttpRequest req) =>
{
    var body = await JsonNode.ParseAsync(req.Body);
    var query = body?["query"]?.GetValue<string>() ?? "";
    if (Demo.LogAnalyticsRows(exposure, query) is { } canned) return Results.Json(canned);
    return Results.Json(new
    {
        tables = new[]
        {
            new
            {
                name = "PrimaryResult",
                columns = new[] { new { name = "Query", type = "string" }, new { name = "Matches", type = "long" } },
                rows = new[] { new object[] { query.Length > 120 ? query[..120] : query, 1 } },
            },
        },
    });
});

// ── Defender for Endpoint ──────────────────────────────────────────────────────────────────────
app.MapGet("/api/machines", (HttpRequest req) =>
{
    var filter = req.Query["$filter"].ToString();
    var all = entities["machines"]!.AsObject().Select(kv => kv.Value!.DeepClone()).ToList();
    // $filter=computerDnsName eq '…' (lookups) or aadDeviceId eq … (Intune alias resolution).
    var match = all.Where(m => filter.Contains(m!["computerDnsName"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase)
                               || (m["aadDeviceId"]?.GetValue<string>() is { } aad && filter.Contains(aad, StringComparison.OrdinalIgnoreCase))).ToList();
    return Results.Json(new { value = match });
});
app.MapGet("/api/machines/{id}", (string id) => Entity("machines", id));
app.MapGet("/api/machines/{id}/logonusers", (string id) => Results.Json(new { value = new[] { new { accountName = "spatel", accountDomain = "CONTOSO", isDomainAdmin = false, lastSeen = DateTimeOffset.UtcNow.AddMinutes(-30) } } }));
app.MapGet("/api/machines/{id}/alerts", () => Results.Json(new { value = Array.Empty<object>() }));
app.MapGet("/api/ips/{ip}/stats", (string ip) => Entity("ips", ip, new { ipAddress = ip, orgPrevalence = 0, communicationCount = 0 }));
app.MapGet("/api/ips/{ip}/alerts", (string ip) => Results.Json(new { value = Array.Empty<object>() }));
app.MapGet("/api/files/{hash}", (string hash) => Entity("files", hash));
app.MapGet("/api/files/{hash}/stats", (string hash) => Results.Json(new { sha256 = hash, orgPrevalence = 1, globalPrevalence = 3 }));
app.MapGet("/api/domains/{domain}/stats", (string domain) => Entity("domains", domain, new { host = domain, orgPrevalence = 1 }));
app.MapGet("/api/recommendations", () => Results.Json(new { value = exposure["recommendations"]!.DeepClone() }));

// ── Intune and Windows Autopatch (exposure remediation) ──────────────────────────────────────────
app.MapGet("/v1.0/deviceManagement/managedDevices", (HttpRequest req) =>
{
    var filter = req.Query["$filter"].ToString();
    var all = exposure["managedDevices"]!.AsArray().Select(d => d!.DeepClone()).ToList();
    return Results.Json(new { value = all.Where(d => filter.Contains(d!["azureADDeviceId"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase)).ToList() });
});
app.MapGet("/v1.0/deviceManagement/managedDevices/{id}", (string id) =>
    exposure["managedDevices"]!.AsArray().FirstOrDefault(d => d!["id"]!.GetValue<string>() == id) is { } d ? Results.Json(d.DeepClone()) : NotFound());
app.MapGet("/beta/admin/windows/updates/catalog/entries", () => Results.Json(new { value = exposure["qualityUpdates"]!.DeepClone() }));

// Brokered writes. The demo runs the broker in dry run, so these normally aren't reached; if BROKER_EXECUTE is
// turned on they record the call and answer like Defender/Graph would.
foreach (var (method, pattern) in new[]
{
    ("POST", "/api/machines/{id}/isolate"), ("POST", "/api/machines/{id}/unisolate"), ("POST", "/api/machines/{id}/runAntiVirusScan"),
    ("POST", "/api/machines/{id}/collectInvestigationPackage"), ("POST", "/api/machines/{id}/restrictCodeExecution"),
    ("POST", "/api/machines/{id}/unrestrictCodeExecution"), ("POST", "/api/machines/{id}/StopAndQuarantineFile"),
    ("POST", "/api/machines/{id}/tags"), ("POST", "/api/indicators"), ("DELETE", "/api/indicators/{id}"),
    ("PATCH", "/v1.0/users/{id}"), ("POST", "/v1.0/users/{id}/revokeSignInSessions"),
    ("POST", "/v1.0/identityProtection/riskyUsers/confirmCompromised"), ("POST", "/v1.0/identityProtection/riskyUsers/dismiss"),
    ("PATCH", "/v1.0/servicePrincipals/{id}"),
    ("POST", "/beta/security/collaboration/analyzedEmails/remediate"),
    ("PATCH", "/v1.0/security/incidents/{id}"), ("POST", "/v1.0/security/incidents/{id}/comments"),
    ("POST", "/v1.0/security/rules/detectionRules"), ("PATCH", "/v1.0/security/rules/detectionRules/{id}"),
    ("POST", "/v1.0/deviceManagement/managedDevices/{id}/syncDevice"), ("POST", "/v1.0/deviceManagement/managedDevices/{id}/windowsDefenderUpdateSignatures"),
    ("POST", "/beta/admin/windows/updates/deployments"), ("POST", "/beta/admin/windows/updates/deployments/{id}/audience/updateAudience"),
})
{
    app.MapMethods(pattern, [method], async (HttpRequest req) =>
    {
        var body = req.ContentLength > 0 ? await JsonNode.ParseAsync(req.Body) : null;
        writes.Enqueue(new { at = DateTimeOffset.UtcNow, method, path = req.Path.Value, body });
        return Results.Json(new { id = Guid.NewGuid(), status = "Pending", mocked = true });
    });
}

// Sentinel analytics rules (ARM, create/disable_detection_rule target sentinel). Demo mode routes ARM to this mock.
var armRules = new ConcurrentDictionary<string, JsonNode>();
app.MapPut("/subscriptions/{**rest}", async (HttpRequest req) =>
{
    var body = await JsonNode.ParseAsync(req.Body);
    writes.Enqueue(new { at = DateTimeOffset.UtcNow, method = "PUT", path = req.Path.Value, body });
    armRules[req.Path.Value!] = body!;
    return Results.Json(body);
});
app.MapGet("/subscriptions/{**rest}", (HttpRequest req) => armRules.TryGetValue(req.Path.Value!, out var r) ? Results.Json(r) : NotFound());

app.MapFallback((HttpRequest req) => Results.Json(new { error = new { code = "NotFound", message = $"mock-msapi has no route for {req.Method} {req.Path}" } }, statusCode: 404));
app.Run();
return 0;

IResult Entity(string kind, string key, object? fallback = null) =>
    entities[kind]?[key] is { } e ? Results.Json(e.DeepClone()) : fallback is not null ? Results.Json(fallback) : NotFound();

static IResult NotFound() => Results.Json(new { error = new { code = "NotFound", message = "not in the demo fixtures" } }, statusCode: 404);

/// <summary>Canned query results for the exposure page and the demo detection back-test.</summary>
static class Demo
{
    /// <summary>The back-testable query in docs/guides/08: a demo rule for encoded PowerShell downloads.</summary>
    public const string BacktestMarker = "EncodedCommand";

    public static object? HuntingRows(JsonObject exposure, string query)
    {
        if (query.Contains("DeviceTvmSoftwareVulnerabilities", StringComparison.Ordinal) && query.Contains("DeviceInfo", StringComparison.Ordinal))
            return new { schema = Array.Empty<object>(), results = exposure["vulnerabilities"]!.DeepClone() };
        if (query.Contains("ExposureGraphEdges", StringComparison.Ordinal))
            return new { schema = Array.Empty<object>(), results = exposure["attackPaths"]!.DeepClone() };
        if (query.Contains(BacktestMarker, StringComparison.OrdinalIgnoreCase)) return new { schema = Array.Empty<object>(), results = BacktestHits() };
        return null;
    }

    public static object? LogAnalyticsRows(JsonObject exposure, string query)
    {
        if (!query.Contains(BacktestMarker, StringComparison.OrdinalIgnoreCase)) return null;
        var rows = BacktestHits().Select(h => new object[] { h["TimeGenerated"]!, h["DeviceName"]!, h["AccountUpn"]! }).ToArray();
        return new
        {
            tables = new[] { new { name = "PrimaryResult", columns = new[] { new { name = "TimeGenerated", type = "datetime" }, new { name = "DeviceName", type = "string" }, new { name = "AccountUpn", type = "string" } }, rows } },
        };
    }

    /// <summary>Two weeks of a handful of hits a day across three devices: a rule an approver would accept.</summary>
    private static List<Dictionary<string, object>> BacktestHits()
    {
        var devices = new[] { ("ws-0142.contoso.com", "sam.patel@contoso.com"), ("ws-0077.contoso.com", "ana.lopez@contoso.com"), ("srv-build-02.contoso.com", "svc-build@contoso.com") };
        var hits = new List<Dictionary<string, object>>();
        var today = DateTimeOffset.UtcNow.Date;
        for (var day = 0; day < 14; day++)
            for (var n = 0; n < (day % 4) + (day == 2 ? 6 : 1); n++)
            {
                var (dev, upn) = devices[(day + n) % devices.Length];
                var at = new DateTimeOffset(today.AddDays(-day).AddHours(8 + n), TimeSpan.Zero);
                hits.Add(new() { ["Timestamp"] = at.ToString("O"), ["TimeGenerated"] = at.ToString("O"), ["DeviceName"] = dev, ["AccountUpn"] = upn, ["FileName"] = "powershell.exe" });
            }
        return hits;
    }
}

static class Fixtures
{
    public static List<JsonObject> LoadIncidents(string dir) =>
        Directory.GetFiles(dir, "*.json").Order(StringComparer.Ordinal)
            .Select(f => JsonNode.Parse(File.ReadAllText(f))!.AsObject()).ToList();

    /// <summary>Incidents with timestamps relative to now (so the board's lookback window always includes them).</summary>
    public static List<JsonObject> Fresh(List<JsonObject> incidents)
    {
        var started = Started;
        return incidents.Select(i =>
        {
            var o = i.DeepClone().AsObject();
            var ago = o["_minutesAgo"]?.GetValue<int>() ?? 10;
            o.Remove("_minutesAgo");
            var created = started.AddMinutes(-ago);
            o["createdDateTime"] = created.ToString("O");
            o["lastUpdateDateTime"] = started.ToString("O");
            o["incidentWebUrl"] = $"https://security.microsoft.com/incidents/{o["id"]}";
            foreach (var a in o["alerts"]!.AsArray())
            {
                a!["firstActivityDateTime"] = created.ToString("O");
                a["lastActivityDateTime"] = created.AddMinutes(2).ToString("O");
            }
            return o;
        }).ToList();
    }

    /// <summary>Fixed for the process lifetime, so incidents don't look "updated" on every poll.</summary>
    private static readonly DateTimeOffset Started = DateTimeOffset.UtcNow;
}
