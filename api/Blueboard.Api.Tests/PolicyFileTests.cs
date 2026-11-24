using Blueboard.Contracts;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Data;
using Blueboard.Api.Mcp;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Issues #9, #11 and #5: strict policy files, warnings, the shared assessment path, typed confirmation and limits.</summary>
public class PolicyFileTests
{
    private const string Device = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";

    private static readonly IncidentContext Incident = new("42", JsonDocument.Parse($$"""
        { "alerts": [ { "evidence": [
          { "@odata.type": "#microsoft.graph.security.deviceEvidence", "mdeDeviceId": "{{Device}}", "deviceDnsName": "fin-lt-1.contoso.local" },
          { "@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": { "userPrincipalName": "j.doe@contoso.com", "azureAdUserId": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f" } }
        ] } ] }
        """).RootElement);

    [Fact]
    public void Example_policy_file_is_valid()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "../../../../../policy.example.json");
        var p = Policy.LoadFile(path);
        Assert.Equal(1, p.Version);
        Assert.Contains("run_av_scan", p.AutoApprove);
    }

    [Fact]
    public void Unknown_key_fails_with_its_name()
    {
        var ex = Assert.Throws<PolicyException>(() => Policy.Parse("""{ "version": 1, "auto_aprove": ["run_av_scan"] }"""));
        Assert.Contains("unknown key auto_aprove", ex.Message);
    }

    [Fact]
    public void Unknown_nested_key_fails() =>
        Assert.Contains("limits.agent.posts", Assert.Throws<PolicyException>(() => Policy.Parse("""{ "limits": { "agent": { "posts": { "capacity": 1, "per_seconds": 1 } } } }""")).Message);

    [Theory]
    [InlineData("""{ "auto_approve": ["isolate_devic"] }""", "unknown action kind isolate_devic")]
    [InlineData("""{ "require_two_approvers": ["nope"] }""", "require_two_approvers: unknown action kind nope")]
    [InlineData("""{ "version": 2 }""", "version must be 1")]
    [InlineData("""{ "expiry_hours": 0 }""", "expiry hours")]
    [InlineData("""{ "limits": { "agent": { "hunt": { "capacity": 0, "per_seconds": 60 } } } }""", "limits.agent.hunt")]
    [InlineData("""{ "auto_approve": "run_av_scan" }""", "invalid value at auto_approve")]
    public void Invalid_values_fail(string json, string expected) =>
        Assert.Contains(expected, Assert.Throws<PolicyException>(() => Policy.Parse(json)).Message);

    [Fact]
    public void Missing_configured_file_fails() =>
        Assert.Throws<PolicyException>(() => Policy.LoadFile("/nonexistent/policy.json"));

    [Fact]
    public void Destructive_kind_in_auto_approve_is_warned_and_ignored()
    {
        var p = Policy.Parse("""{ "auto_approve": ["isolate_device"] }""");
        Assert.Contains(PolicyReport.WarningsFor(p), w => w.StartsWith("isolate_device is in auto_approve but is destructive, so it is ignored"));
        Assert.Equal("approval", PolicyReport.ModeOf("isolate_device", p));
    }

    [Fact]
    public void Missing_protection_and_scope_check_are_warned()
    {
        var w = PolicyReport.WarningsFor(Policy.Parse("""{ "require_target_in_incident": false }"""));
        Assert.Contains(w, x => x.StartsWith("protected_users is empty"));
        Assert.Contains(w, x => x.StartsWith("require_target_in_incident is off"));
    }

    [Fact]
    public void Report_hides_lists_unless_asked()
    {
        var p = new Policy { ProtectedDevices = ["dc01"] };
        Assert.Null(PolicyReport.Build(p).Lists);
        Assert.Equal(1, PolicyReport.Build(p).Protected.Devices);
        Assert.Equal(["dc01"], PolicyReport.Build(p, includeLists: true).Lists!.Devices);
    }

    [Fact]
    public void Every_kind_has_a_target_type_and_a_mode()
    {
        var report = PolicyReport.Build(new Policy { Disabled = ["purge_email"], RequireTwoApprovers = ["disable_user"] });
        Assert.Equal(Catalog.All.Count, report.Actions.Count);
        Assert.All(report.Actions, a => Assert.Contains(a.Target, new[] { "device", "user", "app", "indicator", "email", "incident" }));
        Assert.Equal("disabled", report.Actions.Single(a => a.Kind == "purge_email").Mode);
        Assert.Equal("two_approvers", report.Actions.Single(a => a.Kind == "disable_user").Mode);
        Assert.Equal("auto", report.Actions.Single(a => a.Kind == "run_av_scan").Mode);
    }

    // ── one evaluation path (#11, #8) ─────────────────────────────────────────────────────────

    public static TheoryData<string, string, bool> Fixtures => new()
    {
        { "isolate_device", $$"""{"machine_id":"{{Device}}"}""", true },
        { "run_av_scan", $$"""{"machine_id":"{{Device}}"}""", true },
        { "run_av_scan", $$"""{"machine_id":"{{new string('0', 40)}}"}""", true },
        { "run_av_scan", $$"""{"machine_id":"{{Device}}"}""", false },
        { "disable_user", """{"user":"j.doe@contoso.com"}""", true },
        { "disable_user", """{"user":"breakglass@contoso.com"}""", true },
        { "block_indicator", """{"indicator_type":"domain","value":"contoso.com","title":"test block"}""", true },
        { "add_incident_comment", """{"incident_id":"42","comment":"hi"}""", true },
        { "add_incident_comment", """{"incident_id":"42","comment":"hi"}""", false },
        { "update_incident", """{"incident_id":"999","status":"resolved"}""", true },
        { "reset_password", """{"user":"j.doe@contoso.com"}""", true },
        { "purge_email", """{"messages":[{"network_message_id":"abcdefgh12","recipient":"j.doe@contoso.com"}]}""", true },
    };

    private static readonly Policy Strict = new()
    {
        ProtectedUsers = ["breakglass@contoso.com"], ProtectedIndicators = ["contoso.com"], Disabled = ["reset_password"],
        RequireTwoApprovers = ["disable_user", "purge_email"], ConfirmTarget = ["isolate_device"], ExpiryHoursByKind = new() { ["isolate_device"] = 1 },
    };

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Assessment_matches_the_policy_decision(string kind, string json, bool linked)
    {
        var def = Catalog.Get(kind);
        var p = def.Validate(JsonDocument.Parse(json).RootElement);
        var inc = linked ? Incident : null;
        var decision = PolicyEngine.Evaluate(def, p, inc, Strict);
        var a = PolicyEngine.Assess(def, p, inc, Strict);
        Assert.Equal(decision.Outcome, a.Outcome);
        Assert.Equal(decision.Notes, a.Notes);
        Assert.Equal(decision.Outcome switch { Outcome.Reject => "rejected", Outcome.Auto => "approved", _ => "pending_approval" }, a.Status);
        Assert.Equal(decision.Outcome == Outcome.NeedsApproval ? Strict.ApprovalsFor(kind) : 0, a.ApprovalsRequired);
    }

    [Fact]
    public void Assessment_summaries_read_as_the_preview_shows_them()
    {
        Assessment A(string kind, object prms) { var d = Catalog.Get(kind); return PolicyEngine.Assess(d, d.Validate(JsonSerializer.SerializeToElement(prms)), Incident, Strict); }
        Assert.Equal("Runs automatically", A("run_av_scan", new { machine_id = Device }).Summary);
        Assert.Equal("Needs approval", A("isolate_device", new { machine_id = Device }).Summary);
        Assert.Equal("Needs two approvals", A("disable_user", new { user = "j.doe@contoso.com" }).Summary);
        Assert.Equal("Will be rejected: breakglass@contoso.com is a protected user", A("disable_user", new { user = "breakglass@contoso.com" }).Summary);
        Assert.True(A("isolate_device", new { machine_id = Device }).ConfirmTarget);
        Assert.Equal(1, A("isolate_device", new { machine_id = Device }).ExpiresInHours);
        Assert.Equal(4, A("release_device", new { machine_id = Device }).ExpiresInHours);
    }

    [Fact]
    public void Two_approver_kinds_never_auto_run()
    {
        var p = new Policy { RequireTwoApprovers = ["run_av_scan"] };
        var d = Catalog.Get("run_av_scan");
        Assert.Equal(Outcome.NeedsApproval, PolicyEngine.Evaluate(d, d.Validate(JsonSerializer.SerializeToElement(new { machine_id = Device })), Incident, p).Outcome);
    }

    [Fact]
    public void Confirm_names_include_every_alias_with_the_dns_name_first()
    {
        var d = Catalog.Get("isolate_device");
        var names = PolicyEngine.ConfirmNames(d, d.Validate(JsonSerializer.SerializeToElement(new { machine_id = Device })), Incident);
        Assert.Equal("fin-lt-1.contoso.local", names[0]);
        Assert.Contains("fin-lt-1", names);
        Assert.Contains(Device, names);
        var u = Catalog.Get("disable_user");
        Assert.Equal("j.doe@contoso.com", PolicyEngine.ConfirmNames(u, u.Validate(JsonSerializer.SerializeToElement(new { user = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f" })), Incident)[0]);
    }

    // ── rate limits (#5) ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Humans_get_higher_defaults_and_overrides_apply_per_bucket()
    {
        var l = Policy.Parse("""{ "limits": { "agent": { "hunt": { "capacity": 3, "per_seconds": 60 } } } }""").Limits;
        Assert.Equal(3, l.For("agent", "hunt").Capacity);
        Assert.Equal(60, l.For("agent", "post").Capacity);
        Assert.True(l.For("human", "hunt").Capacity > l.For("agent", "hunt").Capacity);
        Assert.Equal(5, l.For("agent", "action_request").Capacity);
        Assert.Equal(600, l.For("agent", "action_request").PerSeconds);
        Assert.Equal(10, l.PendingActionsPerIncident);
    }

    [Theory]
    [InlineData(0.0, 10, 60, 6)]
    [InlineData(0.5, 10, 60, 3)]
    [InlineData(0.99, 60, 60, 1)]
    [InlineData(0.0, 5, 600, 120)]
    public void Retry_after_is_time_to_the_next_whole_token(double available, int capacity, int per, int expected) =>
        Assert.Equal(expected, RateLimiter.RetryAfter(available, new RateLimit(capacity, per)));

    [Fact]
    public void Mcp_rate_limit_error_names_the_tool() =>
        Assert.Equal("error: rate limited: run_hunting_query, retry in 6s", BoardTools.RateLimitedText("run_hunting_query", 6));
}
