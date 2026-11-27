using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>
/// Where the perception-gap features meet: auto-revert pairs for connector and detection kinds, the requester-risk
/// automation condition, NeverAuto kinds never running under a rule, and the timeline's undo pairs.
/// </summary>
public class CrossWorkstreamTests
{
    private const string Device = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";

    private static IncidentContext Incident() => new("42", JsonDocument.Parse($$"""
        { "severity": "high", "alerts": [ { "serviceSource": "microsoftDefenderForEndpoint", "evidence": [
          { "@odata.type": "#microsoft.graph.security.deviceEvidence", "mdeDeviceId": "{{Device}}", "deviceDnsName": "fin-lt-1.contoso.local" }
        ] } ] }
        """).RootElement);

    private static AutoRuleSpec Rule(int? maxRisk = null) => new(0.9, ["high"], null, 3, 1, null, 60, false, maxRisk);

    private static Policy Ceiling(AutoRuleSpec rule) => new()
    {
        Automation = new AutomationPolicy { ConditionalAutoAllowed = ["isolate_device"], Rules = new() { ["isolate_device"] = rule } },
    };

    private static AutomationFacts Facts(int? risk) => new("triage-agent", [new VerdictFact("analyst", "human", "truePositive", 0.95)], 0, 0, risk);

    private static PolicyDecision Isolate(Policy p, AutomationFacts f)
    {
        var def = Catalog.Get("isolate_device");
        return PolicyEngine.Evaluate(def, def.Validate(JsonSerializer.SerializeToElement(new { machine_id = Device })), Incident(), p, f);
    }

    // ── reverse pairs ──────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("okta_suspend_user", "okta_unsuspend_user")]
    [InlineData("create_detection_rule", "disable_detection_rule")]
    public void Connector_and_detection_kinds_have_their_reverse(string kind, string reverse)
    {
        Assert.True(Reversal.IsReversible(kind));
        Assert.Equal(reverse, Reversal.ReverseKind[kind]);
    }

    [Theory]
    [InlineData("okta_unsuspend_user")] // recovery direction: never re-suspend automatically
    [InlineData("okta_clear_user_sessions")]
    [InlineData("okta_reset_factors")]
    [InlineData("intune_expedite_quality_update")]
    [InlineData("intune_sync_device")]
    [InlineData("disable_detection_rule")]
    [InlineData("purge_email")]
    public void Irreversible_and_recovery_kinds_have_no_automatic_revert(string kind) => Assert.False(Reversal.IsReversible(kind));

    [Fact]
    public void Every_connector_reverse_pair_in_the_containing_direction_is_in_the_map()
    {
        foreach (var (k, v) in Catalog.ConnectorReverseKinds.Where(kv => Catalog.Get(kv.Key).Stage != "recover"))
            Assert.Equal(v, Reversal.ReverseKind[k]);
    }

    [Fact]
    public void Okta_suspend_reverse_params_pass_the_unsuspend_validation()
    {
        var (k, p, _) = Reversal.Build("okta_suspend_user", new JsonObject { ["user"] = "00uabc123def456ghi78" }, null);
        Assert.Equal("okta_unsuspend_user", k);
        Assert.Equal("00uabc123def456ghi78", Catalog.Get(k!).Validate(JsonSerializer.SerializeToElement(p))["user"]!.GetValue<string>());
    }

    [Fact]
    public void Detection_rule_reverse_names_the_creating_action()
    {
        var id = Guid.NewGuid();
        var (k, p, _) = Reversal.Build("create_detection_rule", new JsonObject(), null, id);
        Assert.Equal("disable_detection_rule", k);
        Assert.Equal(id.ToString(), Catalog.Get(k!).Validate(JsonSerializer.SerializeToElement(p))["rule_action_id"]!.GetValue<string>());
        var (none, _, why) = Reversal.Build("create_detection_rule", new JsonObject(), null);
        Assert.Null(none);
        Assert.Contains("creating action's id", why);
    }

    [Fact]
    public void Every_automatic_reverse_is_also_a_timeline_undo_pair()
    {
        foreach (var (kind, reverse) in Reversal.ReverseKind)
            Assert.Equal(kind, IncidentTimeline.Reverts[reverse]);
    }

    // ── max_requester_risk ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Requester_risk_at_or_below_the_limit_lets_the_rule_run()
    {
        var d = Isolate(Ceiling(Rule(40)), Facts(40));
        Assert.Equal(Outcome.Auto, d.Outcome);
        Assert.Equal("isolate_device@file", d.AutoRule);
    }

    [Fact]
    public void Requester_risk_above_the_limit_falls_back_to_approval()
    {
        var d = Isolate(Ceiling(Rule(40)), Facts(41));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains("agent risk score is 41") && n.Contains("max_requester_risk 40"));
    }

    [Fact]
    public void Unknown_requester_risk_fails_the_condition()
    {
        var d = Isolate(Ceiling(Rule(100)), Facts(null));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains("has no agent risk score"));
    }

    [Fact]
    public void Without_max_requester_risk_the_score_is_not_needed()
    {
        Assert.Equal(Outcome.Auto, Isolate(Ceiling(Rule()), Facts(null)).Outcome);
        Assert.Equal(Outcome.Auto, Isolate(Ceiling(Rule()), Facts(99)).Outcome);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(101)]
    public void Max_requester_risk_out_of_range_stops_start_up(int v) =>
        Assert.Contains("max_requester_risk must be 0–100", Assert.Throws<PolicyException>(() => Policy.Parse($$"""
            { "automation": { "conditional_auto_allowed": ["isolate_device"],
              "rules": { "isolate_device": { "severities": ["high"], "revert_after_minutes": 60, "max_requester_risk": {{v}} } } } }
            """)).Message);

    [Fact]
    public void Max_requester_risk_is_read_from_policy_json_and_described()
    {
        var p = Policy.Parse("""
            { "automation": { "conditional_auto_allowed": ["isolate_device"],
              "rules": { "isolate_device": { "severities": ["high"], "revert_after_minutes": 60, "max_requester_risk": 30 } } } }
            """);
        Assert.Equal(30, p.ActiveRules["isolate_device"].Spec.MaxRequesterRisk);
        Assert.Contains("agent risk score is known and ≤ 30", PolicyReport.Build(p).ToText());
    }

    [Fact]
    public void Raising_or_removing_max_requester_risk_is_loosening_and_lowering_or_adding_it_is_tightening()
    {
        Assert.True(AutomationRules.RuleLooser(Rule(30), Rule(50)));
        Assert.True(AutomationRules.RuleLooser(Rule(30), Rule()));
        Assert.False(AutomationRules.RuleLooser(Rule(50), Rule(30)));
        Assert.False(AutomationRules.RuleLooser(Rule(), Rule(30)));
    }

    // ── NeverAuto ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Never_auto_kinds_are_an_error_in_conditional_auto_allowed()
    {
        var ex = Assert.Throws<PolicyException>(() => Policy.Parse("""{ "automation": { "conditional_auto_allowed": ["create_detection_rule"] } }"""));
        Assert.Contains("create_detection_rule always needs a human approver", ex.Message);
    }

    [Fact]
    public void Never_auto_kinds_get_no_rule_from_an_override_or_the_engine()
    {
        Assert.Contains(AutomationRules.Problems("create_detection_rule", Rule(), new Policy()), e => e.Contains("always needs a human approver"));
        // Even a hand-built policy that somehow carries a rule for it never auto-runs.
        var def = Catalog.Get("create_detection_rule");
        var forced = new Policy { AutoApprove = ["create_detection_rule"] } with
        {
            ActiveRules = new Dictionary<string, ActiveRule> { ["create_detection_rule"] = new("create_detection_rule@file", Rule()) },
        };
        var p = new JsonObject { ["target"] = "defender", ["name"] = "rule", ["query"] = "DeviceEvents | take 1", ["backtest_id"] = Guid.NewGuid().ToString() };
        Assert.Equal(Outcome.NeedsApproval, PolicyEngine.Evaluate(def, p, Incident(), forced, Facts(0)).Outcome);
    }
}
