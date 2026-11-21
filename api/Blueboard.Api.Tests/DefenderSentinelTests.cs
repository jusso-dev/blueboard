using System.Net;
using System.Text;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Http;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>
/// Regression and capability tests for the line-by-line robustness fixes, expanded Defender XDR / Sentinel actions
/// and evidence extraction, Log Analytics KQL, starter policy templates, and OpenAPI/MCP interoperability.
/// </summary>
public class DefenderSentinelTests
{
    private const string Device = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";
    private const string Sha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
    private const string UserOid = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f";
    private const string SpOid = "bb22cc33-dd44-45ee-99ff-001122334455";

    private static IncidentContext RichIncident() => new("1005", JsonDocument.Parse($$"""
        {
          "id": "1005",
          "alerts": [
            {
              "mitreTechniques": ["T1528", "T1003.001"],
              "evidence": [
                { "@odata.type": "#microsoft.graph.security.deviceEvidence", "mdeDeviceId": "{{Device}}" },
                { "@odata.type": "#microsoft.graph.security.deviceEvidence", "mdeDeviceId": "{{Device}}", "deviceDnsName": "dc01.contoso.local", "lastIpAddress": "10.0.0.5" },
                { "@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": { "azureAdUserId": "{{UserOid}}" } },
                { "@odata.type": "#microsoft.graph.security.mailboxConfigurationEvidence", "mailboxPrimaryAddress": "ceo@contoso.com", "externalDirectoryObjectId": "{{UserOid}}" },
                { "@odata.type": "#microsoft.graph.security.fileHashEvidence", "algorithm": "FileSha1", "value": "{{Sha1}}" },
                { "@odata.type": "#microsoft.graph.security.fileEvidence", "fileDetails": { "fileName": "dropper1.exe" } },
                { "@odata.type": "#microsoft.graph.security.fileEvidence", "fileDetails": { "fileName": "dropper2.exe" } },
                { "@odata.type": "#microsoft.graph.security.dnsEvidence", "domainName": "c2.evil.example.", "hostIpAddress": { "ipAddress": "198.51.100.77" } },
                { "@odata.type": "#microsoft.graph.security.oauthApplicationEvidence", "appId": "aa11bb22-cc33-44dd-88ee-ff0011223344", "objectId": "{{SpOid}}", "displayName": "DocViewer Sync" },
                { "@odata.type": "#microsoft.graph.security.azureResourceEvidence", "resourceId": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1", "resourceName": "kv1", "resourceType": "Microsoft.KeyVault/vaults" }
              ]
            }
          ]
        }
        """).RootElement);

    [Fact]
    public void Entities_merge_partial_aliases_and_extract_cloud_sentinel_evidence()
    {
        var e = Entities.Extract(RichIncident().Data);

        var dev = Assert.Single(e.Devices);
        Assert.Equal(Device, dev.MdeDeviceId);
        Assert.Equal("dc01.contoso.local", dev.Name);

        var user = Assert.Single(e.Users);
        Assert.Equal(UserOid, user.AadUserId);
        Assert.Equal("ceo@contoso.com", user.Upn);

        // Hash-less files are no longer collapsed into a single null bucket, and FileSha1 is matched case-insensitively.
        Assert.Equal(3, e.Files.Count);
        Assert.Contains(e.Files, f => f.Sha1 == Sha1);
        Assert.Contains(e.Files, f => f.Name == "dropper1.exe");
        Assert.Contains(e.Files, f => f.Name == "dropper2.exe");

        // DNS, OAuth app, and Azure resource evidence are extracted and present in Keys().
        Assert.Contains("c2.evil.example", e.Domains);
        Assert.Contains("198.51.100.77", e.Ips);
        Assert.Contains("10.0.0.5", e.Ips);
        var app = Assert.Single(e.CloudApps);
        Assert.Equal(SpOid, app.ObjectId);
        var res = Assert.Single(e.AzureResources);
        Assert.Equal("kv1", res.Name);

        var keys = e.Keys();
        Assert.Contains(SpOid, keys);
        Assert.Contains("kv1", keys);
        Assert.Contains(Sha1, keys);
    }

    [Fact]
    public void Merged_aliases_enforce_protected_lists_even_when_first_evidence_lacked_name()
    {
        var inc = RichIncident();
        var policy = new Policy { ProtectedDevices = ["dc01.contoso.local"], ProtectedUsers = ["ceo@contoso.com"] };

        var d1 = PolicyEngine.Evaluate(Catalog.Get("restrict_app_execution"),
            Catalog.Get("restrict_app_execution").Validate(JsonSerializer.SerializeToElement(new { machine_id = Device })), inc, policy);
        Assert.Equal(Outcome.Reject, d1.Outcome);

        var d2 = PolicyEngine.Evaluate(Catalog.Get("confirm_user_compromised"),
            Catalog.Get("confirm_user_compromised").Validate(JsonSerializer.SerializeToElement(new { user_id = UserOid })), inc, policy);
        Assert.Equal(Outcome.Reject, d2.Outcome);
    }

    [Fact]
    public void New_defender_and_entra_actions_validate_and_follow_policy()
    {
        var inc = RichIncident();
        var policy = new Policy { AutoApprove = ["tag_device"] };

        // Non-destructive tag_device auto-approves when device is in incident evidence.
        var tagDef = Catalog.Get("tag_device");
        var tagParams = tagDef.Validate(JsonSerializer.SerializeToElement(new { machine_id = Device, tag = "UnderInvestigation" }));
        Assert.Equal("Add", tagParams["action"]!.GetValue<string>());
        Assert.Equal(Outcome.Auto, PolicyEngine.Evaluate(tagDef, tagParams, inc, policy).Outcome);

        // Destructive actions always need approval.
        foreach (var (kind, prms) in new (string, object)[]
        {
            ("restrict_app_execution", new { machine_id = Device }),
            ("unrestrict_app_execution", new { machine_id = Device }),
            ("stop_and_quarantine_file", new { machine_id = Device, sha1 = Sha1 }),
            ("enable_user", new { user = "ceo@contoso.com" }),
            ("confirm_user_compromised", new { user_id = UserOid }),
            ("dismiss_user_risk", new { user_id = UserOid }),
            ("disable_service_principal", new { service_principal_id = SpOid }),
            ("unblock_indicator", new { indicator_id = "12345" }),
        })
        {
            var def = Catalog.Get(kind);
            var valid = def.Validate(JsonSerializer.SerializeToElement(prms));
            Assert.Equal(Outcome.NeedsApproval, PolicyEngine.Evaluate(def, valid, inc, new Policy { AutoApprove = [kind] }).Outcome);
        }
    }

    [Theory]
    [InlineData("block_indicator", """{"indicator_type":"ip","value":"not-an-ip","title":"bad ip"}""")]
    [InlineData("block_indicator", """{"indicator_type":"sha256","value":"short","title":"bad hash"}""")]
    [InlineData("block_indicator", """{"indicator_type":"domain","value":"evil.example","title":"bad days","expires_in_days":30.5}""")]
    [InlineData("update_incident", """{"incident_id":"1005","status":null,"classification":null}""")]
    [InlineData("confirm_user_compromised", """{"user_id":"not-a-guid"}""")]
    [InlineData("disable_service_principal", """{"service_principal_id":"../evil"}""")]
    [InlineData("stop_and_quarantine_file", """{"machine_id":"4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d","sha1":"short"}""")]
    [InlineData("tag_device", """{"machine_id":"4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d","tag":"bad/tag"}""")]
    public void Strict_action_param_validation_rejects_malformed_inputs(string kind, string json) =>
        Assert.Throws<BoardException>(() => Catalog.Get(kind).Validate(JsonDocument.Parse(json).RootElement));

    [Fact]
    public async Task Url_lookup_accepts_full_urls_while_non_url_kinds_still_block_path_chars()
    {
        var handler = new RecordingHandler();
        var ms = new MsClient(new HttpClient(handler), new FakeCredential());
        var db = new Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" });
        var audit = new FakeAudit();
        var enrich = new Enrichment(db, audit, null!, ms);
        var hunter = new Principal(Guid.NewGuid(), "hunter-1", "Hunter", "agent", [Roles.Poster, Roles.Hunter]);

        // Full URL with scheme, path, query and fragment now works cleanly and queries Defender by host.
        await enrich.LookupAsync(hunter, "url", "https://Evil.Example/phish/login?id=1#top", TestContext.Current.CancellationToken);
        Assert.Contains(handler.Requests, r => r.Uri.AbsolutePath == "/api/domains/evil.example/stats");

        // Non-URL entity kinds still strictly reject path/query injection characters.
        await Assert.ThrowsAsync<BoardException>(() => enrich.LookupAsync(hunter, "user", "../me", TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<BoardException>(() => enrich.LookupAsync(hunter, "service_principal", "id?foo=bar", TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Log_analytics_origin_guard_and_result_shaping()
    {
        Assert.Equal("api.loganalytics.io", MsClient.BuildUri(MsApi.LogAnalytics, "/v1/workspaces/00000000-0000-0000-0000-000000000000/query").Host);
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(MsApi.LogAnalytics, "https://api.loganalytics.io.evil.example/v1/workspaces/x/query"));
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(MsApi.LogAnalytics, "/v1/workspaces/../other/query"));

        var raw = JsonDocument.Parse("""
            {"tables":[{"name":"PrimaryResult","columns":[{"name":"UserPrincipalName","type":"string"},{"name":"Hits","type":"long"}],"rows":[["ana@contoso.com",4],["bob@contoso.com",null]]}]}
            """).RootElement;
        var shaped = JsonDocument.Parse(Json.Serialize(Enrichment.ShapeLogAnalyticsResult(raw))).RootElement;
        Assert.Equal(2, shaped.GetProperty("total").GetInt32());
        Assert.False(shaped.GetProperty("truncated").GetBoolean());
        Assert.Equal("ana@contoso.com", shaped.GetProperty("rows")[0].GetProperty("UserPrincipalName").GetString());
        Assert.Equal(4, shaped.GetProperty("rows")[0].GetProperty("Hits").GetInt32());
    }

    [Fact]
    public void Starter_policy_templates_all_validate_cleanly()
    {
        var dir = Path.Combine(OpsTests.RepoRoot(), "templates", "policies");
        var files = Directory.GetFiles(dir, "*.json").Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(3, files.Length);
        foreach (var f in files)
        {
            var policy = Policy.LoadFile(f);
            Assert.Empty(policy.Validate());
        }
    }

    [Fact]
    public void Starter_incident_templates_match_their_expected_playbooks()
    {
        var set = Playbooks.Load(Path.Combine(AppContext.BaseDirectory, "playbooks"));
        var dir = Path.Combine(OpsTests.RepoRoot(), "templates", "incidents");

        static JsonElement Load(string path) => JsonDocument.Parse(File.ReadAllText(path)).RootElement;
        Assert.Equal("bec-aitm-token-theft", set.Match(Load(Path.Combine(dir, "bec-aitm-inbox-rule.json")))?.Id);
        Assert.Equal("oauth-app-consent-abuse", set.Match(Load(Path.Combine(dir, "oauth-app-consent.json")))?.Id);
        Assert.Equal("azure-privilege-escalation", set.Match(Load(Path.Combine(dir, "azure-keyvault-privesc.json")))?.Id);
    }

    [Fact]
    public void Openapi_includes_ops_routes_and_new_sentinel_endpoints()
    {
        var doc = OpenApi.Document();
        var paths = doc["paths"]!.AsObject();
        foreach (var p in new[] { "/api/status", "/api/setup", "/api/manage/broker", "/api/incidents/{id}/sync", "/api/incidents/{id}/playbook" })
            Assert.True(paths.ContainsKey(p), $"missing {p} in OpenAPI document");
        var tools = doc["x-mcp-tools"]!.AsObject();
        foreach (var t in new[] { Tools.SearchMessages, Tools.ListIncidents, Tools.GetIncidentSummary, Tools.RunSentinelQuery, Tools.SyncIncident, Tools.ListActions, Tools.AttachPlaybook })
            Assert.True(tools.ContainsKey(t), $"missing {t} in x-mcp-tools");
    }

    [Fact]
    public void Action_status_words_cover_approved_once_and_expired()
    {
        Assert.Equal("waiting for second approval", IncidentSummary.ActionStatusText["approved_once"]);
        Assert.Equal("expired", IncidentSummary.ActionStatusText["expired"]);
    }

    private sealed class FakeAudit() : Audit(new Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" }))
    {
        public override Task WriteAsync(Guid? actorId, string evt, string? subject, object? detail = null, CancellationToken ct = default) => Task.CompletedTask;
    }
}
