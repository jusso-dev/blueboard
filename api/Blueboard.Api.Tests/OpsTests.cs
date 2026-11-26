using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Core;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Ops;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Records every request and answers 200 with an empty Graph-style body.</summary>
internal sealed class RecordingHandler(HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
{
    public List<(HttpMethod Method, Uri Uri, string? Body, string? Auth)> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Add((request.Method, request.RequestUri!, request.Content is null ? null : await request.Content.ReadAsStringAsync(ct), request.Headers.Authorization?.Parameter));
        return new HttpResponseMessage(status) { Content = new StringContent("""{"value":[]}""", Encoding.UTF8, "application/json") };
    }
}

/// <summary>Hands out an unsigned JWT carrying the given app roles (only the claims are read).</summary>
internal sealed class FakeCredential(params string[] roles) : TokenCredential
{
    public static string Jwt(string[] roles)
    {
        static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return $"{B64("""{"alg":"none","typ":"JWT"}""")}.{B64(JsonSerializer.Serialize(new { aud = "https://graph.microsoft.com", roles }))}.sig";
    }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken ct) => new(Jwt(roles), DateTimeOffset.UtcNow.AddHours(1));
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken ct) => ValueTask.FromResult(GetToken(requestContext, ct));
}

public class OpsTests
{
    private static readonly string[] ReadOnlyRoles =
        ["SecurityIncident.Read.All", "SecurityAlert.Read.All", "ThreatHunting.Read.All", "User.Read.All", "Machine.Read.All"];

    private static Setup NewSetup(RecordingHandler handler, Settings settings, string[] roles, Policy? policy = null)
    {
        var ms = new MsClient(new HttpClient(handler), new FakeCredential(roles));
        var db = new Db(settings with { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" }); // never opened by these checks
        return new Setup(db, settings, policy ?? new Policy(), ms, new Notifier(new HttpClient(handler), db, new Audit(db), ms, settings));
    }

    private static readonly Settings Live = new() { TenantId = "t", ApiAudience = "api://blueboard-test", BrokerExecute = true };

    [Fact]
    public async Task Microsoft_checks_never_write()
    {
        var handler = new RecordingHandler();
        await NewSetup(handler, Live with { NotifyMailFrom = "soc@contoso.com", NotifyMailTo = ["leads@contoso.com"] }, ReadOnlyRoles).MicrosoftAsync(TestContext.Current.CancellationToken);
        Assert.NotEmpty(handler.Requests);
        foreach (var (method, uri, _, _) in handler.Requests)
            Assert.True(method == HttpMethod.Get || (method == HttpMethod.Post && uri.AbsolutePath == "/v1.0/security/runHuntingQuery"),
                $"setup check sent {method} {uri.AbsolutePath}");
    }

    [Fact]
    public async Task Read_only_grant_names_each_missing_write_permission()
    {
        var checks = await NewSetup(new RecordingHandler(), Live, ReadOnlyRoles).MicrosoftAsync(TestContext.Current.CancellationToken);
        var writes = checks.Single(c => c.Id == "writes");
        Assert.Equal(CheckStatus.Failed, writes.Status); // BROKER_EXECUTE=true and nothing can run
        Assert.StartsWith("Not granted: brokered actions will fail", writes.Detail);
        foreach (var perm in Permissions.WriteFor.Values.Select(p => p.Name).Distinct()) Assert.Contains(perm, writes.Detail);
        Assert.Contains("grant-permissions.sh", writes.Fix);
        Assert.Equal(CheckStatus.Ok, checks.Single(c => c.Id == "reads").Status);
    }

    [Fact]
    public async Task Missing_writes_are_a_warning_in_dry_run_and_disabled_kinds_are_skipped()
    {
        var policy = new Policy { Disabled = Catalog.All.Keys.Where(k => k != "isolate_device").ToArray() };
        var checks = await NewSetup(new RecordingHandler(), Live with { BrokerExecute = false }, ReadOnlyRoles, policy).MicrosoftAsync(TestContext.Current.CancellationToken);
        var writes = checks.Single(c => c.Id == "writes");
        Assert.Equal(CheckStatus.Warning, writes.Status);
        Assert.Equal("Not granted: brokered actions will fail: Machine.Isolate.", writes.Detail);
    }

    [Fact]
    public async Task Granted_writes_pass()
    {
        var all = ReadOnlyRoles.Concat(Permissions.WriteFor.Values.Select(p => p.Name)).ToArray();
        var checks = await NewSetup(new RecordingHandler(), Live, all).MicrosoftAsync(TestContext.Current.CancellationToken);
        Assert.All(checks, c => Assert.Equal(CheckStatus.Ok, c.Status));
    }

    [Fact]
    public async Task Failed_read_probe_names_the_permission()
    {
        var checks = await NewSetup(new RecordingHandler(HttpStatusCode.Forbidden), Live, ReadOnlyRoles).MicrosoftAsync(TestContext.Current.CancellationToken);
        var reads = checks.Single(c => c.Id == "reads");
        Assert.Equal(CheckStatus.Failed, reads.Status);
        Assert.Contains("ThreatHunting.Read.All", reads.Detail);
        Assert.Contains("grant-permissions.sh", reads.Fix);
    }

    [Fact]
    public void Write_permissions_match_grant_permissions_script()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot(), "infra", "grant-permissions.sh"));
        var body = Regex.Match(script, @"perm_for\(\) \{(.*?)\n\}", RegexOptions.Singleline).Groups[1].Value;
        var fromScript = new Dictionary<string, string>();
        foreach (Match m in Regex.Matches(body, @"^\s*([a-z_ |]+)\) echo ""\$(MDE|GRAPH)_APP ([^""]+)""", RegexOptions.Multiline))
            foreach (var kind in m.Groups[1].Value.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                fromScript[kind] = $"{(m.Groups[2].Value == "MDE" ? MsApi.Defender : MsApi.Graph)} {m.Groups[3].Value}";
        var fromCode = Permissions.WriteFor.ToDictionary(kv => kv.Key, kv => $"{kv.Value.Api} {kv.Value.Name}");
        Assert.Equal(fromCode.OrderBy(k => k.Key), fromScript.OrderBy(k => k.Key));
        // Every kind is covered by an application permission or (publish_ti_indicator) an Azure role.
        Assert.Equal(Catalog.All.Keys.Order(), Permissions.WriteFor.Keys.Concat(Permissions.AzureRoleFor.Keys).Order());
    }

    internal static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "infra", "grant-permissions.sh"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    // ── notifications ──────────────────────────────────────────────────────────────────────────────
    private const string Hostile = "[click](https://evil.example) <img src=x onerror=alert(1)> **bold** ${{secret}} \n# heading";

    private static Notice HostileNotice() => new("action.pending_approval", Guid.NewGuid(), "Isolate device (MDE)", "Full network isolation of " + Hostile,
        "agent<script>", "90210", Hostile, "high", 2, "https://board.example/approvals#x", "pending_approval");

    [Fact]
    public void Teams_card_escapes_untrusted_text()
    {
        var json = Json.Serialize(Notifier.TeamsCard(HostileNotice()));
        var doc = JsonDocument.Parse(json);
        var texts = doc.RootElement.GetProperty("attachments")[0].GetProperty("content").GetProperty("body")
            .EnumerateArray().SelectMany(b => b.TryGetProperty("facts", out var f) ? f.EnumerateArray().Select(x => x.GetProperty("value").GetString()!) : [b.GetProperty("text").GetString()!])
            .ToList();
        var incident = texts.Single(t => t.Contains("90210"));
        Assert.Contains(@"\[click\]\(https://evil\.example\)", incident); // a literal, not a link
        Assert.Contains(@"\<img", incident);
        Assert.Contains(@"\*\*bold\*\*", incident);
        Assert.DoesNotContain("${{", incident); // template syntax neutralised
        Assert.DoesNotContain("\n", incident);
        Assert.All(texts, t => Assert.DoesNotMatch(@"(?<!\\)\[[^\]]*(?<!\\)\]\(", t));
        // The only link in the card is the board's own.
        var actions = doc.RootElement.GetProperty("attachments")[0].GetProperty("content").GetProperty("actions");
        Assert.Equal("https://board.example/approvals#x", actions[0].GetProperty("url").GetString());
    }

    [Fact]
    public void Mail_html_is_inert()
    {
        var html = Notifier.MailHtml(HostileNotice());
        Assert.DoesNotContain("<img", html);
        Assert.DoesNotContain("<script", html);
        Assert.Contains("&lt;img src=x onerror=alert(1)&gt;", html);
        Assert.Single(Regex.Matches(html, "<a "));
        Assert.Contains("<a href=\"https://board.example/approvals#x\">", html);
    }

    [Fact]
    public void Notices_never_carry_justification()
    {
        // Notice has no justification field at all; the webhook payload is built only from it.
        Assert.DoesNotContain(typeof(Notice).GetProperties(), p => p.Name.Contains("Justification", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("justification", Json.Serialize(Notifier.WebhookPayload(HostileNotice())));
    }

    [Fact]
    public void Webhook_signature_is_hmac_sha256_over_the_raw_body()
    {
        const string body = """{"event":"action.pending_approval"}""";
        var secret = new string('k', 32);
        var expected = "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body)));
        Assert.Equal(expected, Notifier.Sign(body, secret));
    }

    [Theory]
    [InlineData("http://hooks.example.com/x", "https")]
    [InlineData("https://evil.example.com/x", "NOTIFY_ALLOWED_HOSTS")]
    [InlineData("https://hooks.example.com.evil.example/x", "NOTIFY_ALLOWED_HOSTS")]
    [InlineData("https://user:pw@hooks.example.com/x", "credentials")]
    [InlineData("https://hooks.example.com:8443/x", "custom port")]
    public void Notification_urls_need_https_and_an_allowed_host(string url, string problem)
    {
        var n = new Notifier(new HttpClient(), new Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" }), null!, null!,
            new Settings { NotifyAllowedHosts = ["hooks.example.com"] });
        Assert.Contains(problem, n.UrlProblem(url, "NOTIFY_WEBHOOK_URL"));
        Assert.Null(n.UrlProblem("https://hooks.example.com/x", "NOTIFY_WEBHOOK_URL"));
    }

    [Fact]
    public void Sink_errors_never_echo_urls() =>
        Assert.DoesNotContain("https://", Notifier.SafeError(new BoardException("POST https://secret.example/hook?sig=abc failed")));

    // ── audit export ─────────────────────────────────────────────────────────────────────────────
    private const string Dcr = "dcr-0123456789abcdef0123456789abcdef";

    [Fact]
    public void Ingestion_uri_is_built_on_the_exact_endpoint()
    {
        var u = AuditExporter.BuildUri("https://bb-dce-x.australiaeast-1.ingest.monitor.azure.com", Dcr, "Custom-BlueboardAudit_CL");
        Assert.Equal("bb-dce-x.australiaeast-1.ingest.monitor.azure.com", u.Host);
        Assert.Equal($"/dataCollectionRules/{Dcr}/streams/Custom-BlueboardAudit_CL", u.AbsolutePath);
    }

    [Theory]
    [InlineData("http://bb.australiaeast-1.ingest.monitor.azure.com", Dcr)]
    [InlineData("https://ingest.monitor.azure.com.evil.example", Dcr)]
    [InlineData("https://evil.example", Dcr)]
    [InlineData("https://bb.australiaeast-1.ingest.monitor.azure.com", "dcr-../../x")]
    public void Ingestion_uri_refuses_other_hosts_and_crafted_ids(string endpoint, string dcr) =>
        Assert.Throws<InvalidOperationException>(() => AuditExporter.BuildUri(endpoint, dcr, "Custom-BlueboardAudit_CL"));

    [Fact]
    public void Doctor_prints_one_line_per_check_and_how_to_fix()
    {
        var report = new SetupReport(DateTimeOffset.UtcNow, false,
        [
            new("a", "Database", CheckStatus.Ok, "fine"),
            new("b", "Write permissions", CheckStatus.Failed, "Not granted: brokered actions will fail: Machine.Isolate.", "Run ./infra/grant-permissions.sh"),
        ]);
        var text = Setup.Format(report);
        Assert.Contains("OK      Database: fine", text);
        Assert.Contains("FAILED  Write permissions:", text);
        Assert.Contains("How to fix: Run ./infra/grant-permissions.sh", text);
        Assert.EndsWith("at least one check failed" + Environment.NewLine, text);
    }

    [Fact]
    public void Access_warns_until_two_approvers_and_an_admin_have_signed_in()
    {
        static (string, string[]) P(string h, params string[] r) => (h, r);
        Assert.Equal(CheckStatus.Warning, Setup.Access([P("ana", Roles.Poster)], false).Status);
        var one = Setup.Access([P("lead", Roles.Approver, Roles.Admin)], false);
        Assert.Equal(CheckStatus.Warning, one.Status);
        Assert.Contains("own request", one.Detail);
        Assert.Equal(CheckStatus.Warning, Setup.Access([P("a", Roles.Approver), P("b", Roles.Approver)], false).Status); // no admin
        var ok = Setup.Access([P("a", Roles.Approver), P("b", Roles.Approver, Roles.Admin)], false);
        Assert.Equal(CheckStatus.Ok, ok.Status);
        Assert.Contains(ok.Lines!, l => l.Contains("@a") && l.Contains("@b"));
        // require_two_approvers kinds need a third person, so the requester's own approval is never needed.
        Assert.Equal(CheckStatus.Warning, Setup.Access([P("a", Roles.Approver), P("b", Roles.Approver, Roles.Admin)], true).Status);
        Assert.Equal(CheckStatus.Ok, Setup.Access([P("a", Roles.Approver), P("b", Roles.Approver, Roles.Admin), P("c", Roles.Approver)], true).Status);
    }

    [Fact]
    public void Retention_check_reports_off_pending_failed_stale_and_ok()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.Equal(CheckStatus.Warning, Setup.RetentionCheck(0, null, now).Status);
        Assert.Equal(CheckStatus.Ok, Setup.RetentionCheck(365, null, now).Status);
        Assert.Equal(CheckStatus.Failed, Setup.RetentionCheck(365, new RetentionResult(now, now, 365, false, 0, 0, 0, 0, "boom"), now).Status);
        Assert.Equal(CheckStatus.Warning, Setup.RetentionCheck(365, new RetentionResult(now.AddDays(-3), now, 365, false, 0, 0, 0, 0), now).Status);
        var ok = Setup.RetentionCheck(365, new RetentionResult(now.AddHours(-2), now, 365, false, 2, 10, 1, 4), now);
        Assert.Equal(CheckStatus.Ok, ok.Status);
        Assert.Contains("2 incident(s)", ok.Detail);
    }

    [Theory]
    [InlineData("7")]
    [InlineData("-1")]
    public void Retention_days_below_thirty_are_refused(string v) =>
        Assert.Throws<InvalidOperationException>(() => Settings.FromEnvironment(k => k == "RETENTION_DAYS" ? v : null));
}
