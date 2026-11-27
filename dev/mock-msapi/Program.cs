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
    var match = all.Where(m => filter.Contains(m!["computerDnsName"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase)).ToList();
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
})
{
    app.MapMethods(pattern, [method], async (HttpRequest req) =>
    {
        var body = req.ContentLength > 0 ? await JsonNode.ParseAsync(req.Body) : null;
        writes.Enqueue(new { at = DateTimeOffset.UtcNow, method, path = req.Path.Value, body });
        return Results.Json(new { id = Guid.NewGuid(), status = "Pending", mocked = true });
    });
}

// ── Okta, ServiceNow and Jira (WS5 connectors) ─────────────────────────────────────────────────
// The board's connectors point here in the demo (OKTA_ORG_URL, SERVICENOW_INSTANCE_URL, JIRA_BASE_URL). No credential is
// ever sent in demo mode; these answer the exact paths the connectors call. Users mirror the fixture incidents' UPNs.
var oktaUsers = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
foreach (var (id, login, first, last, status, lastLogin) in new[]
{
    ("00udemoana00000000001", "ana.lopez@contoso.com", "Ana", "Lopez", "ACTIVE", -35),
    ("00udemosam00000000002", "sam.patel@contoso.com", "Sam", "Patel", "ACTIVE", -240),
    ("00udemojch00000000003", "j.chen@contoso.com", "Jun", "Chen", "ACTIVE", -12),
})
{
    var u = new JsonObject
    {
        ["id"] = id, ["status"] = status, ["created"] = "2024-02-01T00:00:00.000Z",
        ["lastLogin"] = DateTimeOffset.UtcNow.AddMinutes(lastLogin).ToString("O"),
        ["passwordChanged"] = "2026-09-12T03:14:00.000Z",
        ["profile"] = new JsonObject { ["login"] = login, ["email"] = login, ["firstName"] = first, ["lastName"] = last },
    };
    oktaUsers[id] = u;
    oktaUsers[login] = u;
}
IResult OktaUser(string id) => oktaUsers.TryGetValue(id, out var u) ? Results.Json(u.DeepClone()) : Results.Json(new { errorCode = "E0000007", errorSummary = $"Not found: Resource not found: {id} (User)" }, statusCode: 404);
app.MapPost("/oauth2/v1/token", () => Results.Json(new { access_token = "mock-not-a-token", token_type = "Bearer", expires_in = 3600 }));
app.MapGet("/api/v1/users", (HttpRequest req) => Results.Json(oktaUsers.Values.Distinct().Take(1).Select(u => u.DeepClone())));
app.MapGet("/api/v1/users/{id}", (string id) => OktaUser(id));
app.MapGet("/api/v1/users/{id}/factors", (string id) => Results.Json(id.Contains("jch")
    ? new object[] { new { factorType = "sms", provider = "OKTA", status = "ACTIVE", created = "2026-11-27T00:40:00.000Z" } }
    : new object[] { new { factorType = "push", provider = "OKTA", status = "ACTIVE", created = "2024-02-01T00:00:00.000Z" }, new { factorType = "webauthn", provider = "FIDO", status = "ACTIVE", created = "2025-03-10T00:00:00.000Z" } }));
app.MapGet("/api/v1/users/{id}/groups", (string id) => Results.Json(new[] { new { profile = new { name = "Everyone" } }, new { profile = new { name = id.Contains("sam") ? "Engineering" : "Finance" } } }));
app.MapGet("/api/v1/users/{id}/roles", (string id) => Results.Json(id.Contains("sam") ? new[] { new { type = "APP_ADMIN", label = "Application Administrator" } } : Array.Empty<object>()));
app.MapGet("/api/v1/logs", () => Results.Json(new object[]
{
    new
    {
        published = DateTimeOffset.UtcNow.AddMinutes(-14).ToString("O"), eventType = "user.authentication.auth_via_mfa", displayMessage = "Authentication of user via MFA",
        severity = "INFO", outcome = new { result = "SUCCESS" }, actor = new { alternateId = "j.chen@contoso.com" },
        client = new { ipAddress = "185.220.101.4", userAgent = new { rawUserAgent = "Mozilla/5.0" }, geographicalContext = new { city = "Frankfurt", country = "Germany" } },
    },
    new
    {
        published = DateTimeOffset.UtcNow.AddMinutes(-15).ToString("O"), eventType = "system.mfa.factor.activate", displayMessage = "Activate factor or authenticator (new SMS factor)",
        severity = "INFO", outcome = new { result = "SUCCESS" }, actor = new { alternateId = "j.chen@contoso.com" },
        client = new { ipAddress = "185.220.101.4", userAgent = new { rawUserAgent = "Mozilla/5.0" }, geographicalContext = new { city = "Frankfurt", country = "Germany" } },
    },
}));

var tickets = new ConcurrentDictionary<string, JsonObject>();
var ticketSeq = 10000;
app.MapPost("/oauth_token.do", () => Results.Json(new { access_token = "mock-not-a-token", token_type = "Bearer", expires_in = 1800 }));
app.MapGet("/api/now/table/{table}", (string table) => Results.Json(new { result = tickets.Values.Take(1).Select(t => t.DeepClone()) }));
app.MapPost("/api/now/table/{table}", async (string table, HttpRequest req) =>
{
    var body = (await JsonNode.ParseAsync(req.Body))?.AsObject() ?? new JsonObject();
    var sysId = Guid.NewGuid().ToString("N");
    var number = $"INC{Interlocked.Increment(ref ticketSeq):0000000}";
    body["sys_id"] = sysId;
    body["number"] = number;
    tickets[sysId] = body;
    writes.Enqueue(new { at = DateTimeOffset.UtcNow, method = "POST", path = req.Path.Value, body = body.DeepClone() });
    return Results.Json(new { result = new { sys_id = sysId, number } }, statusCode: 201);
});
app.MapMethods("/api/now/table/{table}/{sysId}", ["PATCH"], async (string table, string sysId, HttpRequest req) =>
{
    var body = await JsonNode.ParseAsync(req.Body);
    writes.Enqueue(new { at = DateTimeOffset.UtcNow, method = "PATCH", path = req.Path.Value, body });
    return tickets.ContainsKey(sysId) ? Results.Json(new { result = new { sys_id = sysId } }) : NotFound();
});
var jiraSeq = 0;
app.MapGet("/rest/api/3/project/{key}", (string key) => Results.Json(new { id = "10000", key, name = "Security Operations" }));
app.MapPost("/rest/api/3/issue", async (HttpRequest req) =>
{
    var body = await JsonNode.ParseAsync(req.Body);
    var n = Interlocked.Increment(ref jiraSeq);
    writes.Enqueue(new { at = DateTimeOffset.UtcNow, method = "POST", path = req.Path.Value, body });
    return Results.Json(new { id = (10000 + n).ToString(), key = $"SOC-{n}", self = $"/rest/api/3/issue/{10000 + n}" }, statusCode: 201);
});
app.MapPost("/rest/api/3/issue/{id}/comment", async (string id, HttpRequest req) =>
{
    writes.Enqueue(new { at = DateTimeOffset.UtcNow, method = "POST", path = req.Path.Value, body = await JsonNode.ParseAsync(req.Body) });
    return Results.Json(new { id = Guid.NewGuid().ToString("N")[..8] }, statusCode: 201);
});
app.MapPost("/rest/api/3/issue/{id}/transitions", () => Results.NoContent());
// Okta brokered writes (reached only if BROKER_EXECUTE is turned on in the demo).
foreach (var pattern in new[] { "/api/v1/users/{id}/lifecycle/suspend", "/api/v1/users/{id}/lifecycle/unsuspend", "/api/v1/users/{id}/lifecycle/reset_factors" })
    app.MapPost(pattern, (HttpRequest req) => { writes.Enqueue(new { at = DateTimeOffset.UtcNow, method = "POST", path = req.Path.Value }); return Results.Ok(); });
app.MapDelete("/api/v1/users/{id}/sessions", (HttpRequest req) => { writes.Enqueue(new { at = DateTimeOffset.UtcNow, method = "DELETE", path = req.Path.Value }); return Results.NoContent(); });

app.MapFallback((HttpRequest req) => Results.Json(new { error = new { code = "NotFound", message = $"mock-msapi has no route for {req.Method} {req.Path}" } }, statusCode: 404));
app.Run();
return 0;

IResult Entity(string kind, string key, object? fallback = null) =>
    entities[kind]?[key] is { } e ? Results.Json(e.DeepClone()) : fallback is not null ? Results.Json(fallback) : NotFound();

static IResult NotFound() => Results.Json(new { error = new { code = "NotFound", message = "not in the demo fixtures" } }, statusCode: 404);

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
                // Optional per-alert activity window (_firstMinutesAgo/_lastMinutesAgo), else the incident's creation time.
                var first = a!["_firstMinutesAgo"] is { } fa ? started.AddMinutes(-fa.GetValue<int>()) : created;
                var last = a["_lastMinutesAgo"] is { } la ? started.AddMinutes(-la.GetValue<int>()) : first.AddMinutes(2);
                a.AsObject().Remove("_firstMinutesAgo");
                a.AsObject().Remove("_lastMinutesAgo");
                a["firstActivityDateTime"] = first.ToString("O");
                a["lastActivityDateTime"] = last.ToString("O");
                a["createdDateTime"] = last.AddMinutes(1).ToString("O");
            }
            Relative(o, started);
            return o;
        }).ToList();
    }

    /// <summary>Evidence timestamps written as "@minutesAgo:N" in a fixture become real times relative to start, so the attack timeline renders.</summary>
    private static void Relative(JsonNode? n, DateTimeOffset started)
    {
        switch (n)
        {
            case JsonObject o:
                foreach (var (k, v) in o.ToList())
                {
                    if (v is JsonValue jv && jv.TryGetValue<string>(out var s) && s.StartsWith("@minutesAgo:", StringComparison.Ordinal)
                        && int.TryParse(s["@minutesAgo:".Length..], out var m))
                        o[k] = started.AddMinutes(-m).ToString("O");
                    else Relative(v, started);
                }
                break;
            case JsonArray a:
                foreach (var x in a) Relative(x, started);
                break;
        }
    }

    /// <summary>Fixed for the process lifetime, so incidents don't look "updated" on every poll.</summary>
    private static readonly DateTimeOffset Started = DateTimeOffset.UtcNow;
}
