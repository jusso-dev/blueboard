using System.Reflection;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Http;
using Blueboard.Api.Mcp;
using Blueboard.Contracts;
using Microsoft.Azure.Functions.Worker;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>
/// WS1 conditional automation: the policy.json ceiling, rule conditions (all in PolicyEngine so simulate, preview,
/// request, approval and execution agree), tighten/loosen classification, file ∩ override merge, and auto-revert.
/// Database-enforced parts (second admin, caps under lock) are in the integration tests.
/// </summary>
public class AutomationTests
{
    private const string Device = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";

    private static IncidentContext Incident(string severity = "high", string source = "microsoftDefenderForEndpoint") => new("42", JsonDocument.Parse($$"""
        { "severity": "{{severity}}", "alerts": [ { "serviceSource": "{{source}}", "evidence": [
          { "@odata.type": "#microsoft.graph.security.deviceEvidence", "mdeDeviceId": "{{Device}}", "deviceDnsName": "fin-lt-1.contoso.local" },
          { "@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": { "userPrincipalName": "j.doe@contoso.com", "azureAdUserId": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f" } }
        ] } ] }
        """).RootElement);

    private static AutoRuleSpec Rule(double conf = 0.9, int revert = 60, bool human = false, string[]? requesters = null) =>
        new(conf, ["high"], ["microsoftDefenderForEndpoint"], 3, 1, requesters, revert, human);

    /// <summary>The balanced example: isolate_device may run on its own under a conservative rule.</summary>
    private static Policy Ceiling(AutoRuleSpec? rule = null, Action<Policy>? _ = null) => new()
    {
        Automation = new AutomationPolicy
        {
            ConditionalAutoAllowed = ["isolate_device", "disable_user", "purge_email"],
            IrreversibleAutoAllowed = ["purge_email"],
            Rules = new() { ["isolate_device"] = rule ?? Rule() },
        },
    };

    private static readonly VerdictFact AnalystTp = new("analyst", "human", "truePositive", 0.95);
    private static AutomationFacts Facts(string requester = "agent", int hour = 0, int incident = 0, params VerdictFact[] verdicts) =>
        new(requester, verdicts.Length == 0 ? [AnalystTp] : verdicts, hour, incident);

    private static PolicyDecision Eval(string kind, object prms, Policy policy, AutomationFacts? facts, IncidentContext? inc = null)
    {
        var def = Catalog.Get(kind);
        return PolicyEngine.Evaluate(def, def.Validate(JsonSerializer.SerializeToElement(prms)), inc ?? Incident(), policy, facts);
    }

    private static PolicyDecision Isolate(Policy policy, AutomationFacts? facts, IncidentContext? inc = null) =>
        Eval("isolate_device", new { machine_id = Device }, policy, facts, inc);

    // ── defaults unchanged ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Default_policy_has_no_automation_and_destructive_kinds_still_need_a_person()
    {
        var p = new Policy();
        Assert.Empty(p.ActiveRules);
        Assert.Equal(Outcome.NeedsApproval, Isolate(p, Facts()).Outcome);
    }

    [Fact]
    public void Example_and_strict_templates_keep_every_destructive_kind_human_gated()
    {
        foreach (var file in new[] { "policy.example.json", "templates/policies/starter-strict-regulated.json", "templates/policies/starter-readonly.json" })
        {
            var p = Policy.LoadFile(Path.Combine(AppContext.BaseDirectory, "../../../../../", file));
            Assert.Empty(p.ActiveRules);
            Assert.Empty(p.Automation.ConditionalAutoAllowed);
        }
    }

    [Fact]
    public void Balanced_template_auto_isolates_with_a_60_minute_revert()
    {
        var p = Policy.LoadFile(Path.Combine(AppContext.BaseDirectory, "../../../../../templates/policies/starter-balanced-soc.json"));
        Assert.Equal(["isolate_device"], p.ActiveRules.Keys);
        Assert.Equal(60, p.ActiveRules["isolate_device"].Spec.RevertAfterMinutes);
        // confirm_target lists isolate_device, so a conditional rule there still needs a typed target from a person
        // when it falls back to approval; the rule itself applies when every condition holds.
        var d = Isolate(p, Facts());
        Assert.Equal(Outcome.Auto, d.Outcome);
        Assert.Equal("isolate_device@file", d.AutoRule);
    }

    // ── conditions ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Rule_runs_on_its_own_when_every_condition_holds()
    {
        var d = Isolate(Ceiling(), Facts());
        Assert.Equal(Outcome.Auto, d.Outcome);
        Assert.Equal("isolate_device@file", d.AutoRule);
        var def = Catalog.Get("isolate_device");
        var a = PolicyEngine.Assess(def, def.Validate(JsonSerializer.SerializeToElement(new { machine_id = Device })), Incident(), Ceiling(), Facts());
        Assert.Equal("approved", a.Status);
        Assert.Equal(60, a.RevertAfterMinutes);
        Assert.Contains("isolate_device@file", a.Summary);
    }

    [Fact]
    public void Requesters_own_verdict_never_corroborates()
    {
        // The agent asks and vouches for itself: no corroboration, so a person decides.
        var d = Isolate(Ceiling(), Facts("agent", 0, 0, new VerdictFact("agent", "agent", "truePositive", 1.0)));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Null(d.AutoRule);
        Assert.Contains(d.Notes, n => n.Contains("other than @agent"));
    }

    [Fact]
    public void Requester_match_is_case_insensitive_so_a_handle_variant_cannot_self_corroborate()
    {
        var d = Isolate(Ceiling(), Facts("Agent", 0, 0, new VerdictFact("agent", "agent", "truePositive", 1.0)));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
    }

    [Fact]
    public void Low_confidence_verdict_falls_back_to_approval_with_a_note()
    {
        var d = Isolate(Ceiling(), Facts("agent", 0, 0, new VerdictFact("analyst", "human", "truePositive", 0.5)));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.StartsWith("automation rule isolate_device@file not applied") && n.Contains("confidence ≥ 0.9"));
    }

    [Fact]
    public void A_dissenting_verdict_blocks_automation()
    {
        var d = Isolate(Ceiling(), Facts("agent", 0, 0, AnalystTp, new VerdictFact("analyst2", "human", "falsePositive", 0.7)));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains("verdicts disagree"));
    }

    [Fact]
    public void Require_human_verdict_ignores_agent_verdicts()
    {
        var d = Isolate(Ceiling(Rule(human: true)), Facts("agent", 0, 0, new VerdictFact("agent2", "agent", "truePositive", 0.99)));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Equal(Outcome.Auto, Isolate(Ceiling(Rule(human: true)), Facts()).Outcome);
    }

    [Theory]
    [InlineData("medium", "microsoftDefenderForEndpoint", "incident severity medium")]
    [InlineData("high", "microsoftDefenderForOffice365", "no alert from microsoftDefenderForEndpoint")]
    public void Severity_and_source_filters_apply(string severity, string source, string note)
    {
        var d = Isolate(Ceiling(), Facts(), Incident(severity, source));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains(note));
    }

    [Fact]
    public void Targets_must_be_in_evidence_even_when_require_target_in_incident_is_off()
    {
        var p = Ceiling() with { RequireTargetInIncident = false };
        var d = Eval("isolate_device", new { machine_id = new string('a', 40) }, p, Facts());
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains("not every target is in the incident evidence"));
    }

    [Fact]
    public void Unlinked_requests_never_auto_run() =>
        Assert.Equal(Outcome.NeedsApproval, PolicyEngine.Evaluate(Catalog.Get("isolate_device"),
            Catalog.Get("isolate_device").Validate(JsonSerializer.SerializeToElement(new { machine_id = Device })), null, Ceiling(), Facts()).Outcome);

    [Fact]
    public void Allowed_requester_list_applies()
    {
        var p = Ceiling(Rule(requesters: ["triage-bot"]));
        Assert.Equal(Outcome.NeedsApproval, Isolate(p, Facts("agent")).Outcome);
        Assert.Equal(Outcome.Auto, Isolate(p, Facts("triage-bot")).Outcome);
    }

    [Theory]
    [InlineData(3, 0, "in the last hour")]
    [InlineData(0, 1, "on incident 42")]
    public void Caps_fall_back_to_approval_not_rejection(int hour, int onIncident, string note)
    {
        var d = Isolate(Ceiling(), Facts("agent", hour, onIncident));
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains("cap reached") && n.Contains(note));
    }

    [Fact]
    public void Protected_lists_always_block_whatever_the_rule_says()
    {
        var p = Ceiling() with { ProtectedDevices = ["fin-lt-1.contoso.local"] };
        var d = Isolate(p, Facts());
        Assert.Equal(Outcome.Reject, d.Outcome);
        Assert.Null(d.AutoRule);
    }

    [Fact]
    public void Missing_facts_never_auto_run() => Assert.Equal(Outcome.NeedsApproval, Isolate(Ceiling(), null).Outcome);

    [Fact]
    public void Automation_pause_turns_every_automatic_decision_into_approval()
    {
        var paused = AutomationRules.Merge(Ceiling(), new Dictionary<string, (KindSetting, long)>(), new AutomationPause(true, "admin1", DateTimeOffset.UtcNow, "incident review"));
        var d = Isolate(paused, Facts());
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains("automation is paused by @admin1"));
        // Non-destructive auto_approve kinds wait too.
        Assert.Equal(Outcome.NeedsApproval, Eval("run_av_scan", new { machine_id = Device }, paused, null).Outcome);
        Assert.Equal(Outcome.Auto, Eval("run_av_scan", new { machine_id = Device }, Ceiling(), null).Outcome);
    }

    [Fact]
    public void Two_approver_kinds_never_run_on_their_own()
    {
        // The file can't list it (validation), and an override that makes it two_approvers drops the rule.
        var e = AutomationRules.Effective("isolate_device", Ceiling(), new KindSetting("two_approvers", false, Rule()));
        Assert.Null(e.Rule);
        Assert.Contains("two_approvers", Assert.Throws<PolicyException>(() => Policy.Parse("""
            { "require_two_approvers": ["isolate_device"], "automation": { "conditional_auto_allowed": ["isolate_device"] } }
            """)).Message);
    }

    // ── policy.json ceiling validation ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("""{ "automation": { "conditional_auto_allowed": ["isolate_devic"] } }""", "automation.conditional_auto_allowed: unknown action kind isolate_devic")]
    [InlineData("""{ "automation": { "conditional_auto_allowed": ["run_av_scan"] } }""", "is not destructive")]
    [InlineData("""{ "automation": { "conditional_auto_allowed": ["purge_email"] } }""", "must also be listed in automation.irreversible_auto_allowed")]
    [InlineData("""{ "automation": { "conditional_auto_allowed": ["isolate_device"], "rules": { "isolate_device": { "min_confidence": 0.9, "severities": ["high"] } } } }""", "revert_after_minutes is required")]
    [InlineData("""{ "automation": { "conditional_auto_allowed": ["isolate_device"], "rules": { "isolate_device": { "min_confidence": 0.5, "severities": ["high"], "revert_after_minutes": 60 } } } }""", "min_confidence must be 0.8")]
    [InlineData("""{ "automation": { "rules": { "isolate_device": { "severities": ["high"], "revert_after_minutes": 60 } } } }""", "not in automation.conditional_auto_allowed")]
    [InlineData("""{ "automation": { "conditional_auto_allowed": ["isolate_device"], "rules": { "isolate_device": { "severities": ["urgent"], "revert_after_minutes": 60 } } } }""", "severities must list")]
    [InlineData("""{ "automation": { "conditional_auto_allowed": ["isolate_device"], "rules": { "isolate_device": { "severities": ["high"], "revert_after_minutes": 60, "max_per_hour": 99 } } } }""", "max_per_hour must be 1–10")]
    [InlineData("""{ "automation": { "auto_isolate": true } }""", "unknown key automation.auto_isolate")]
    [InlineData("""{ "automation": { "conditional_auto_allowed": ["purge_email"], "irreversible_auto_allowed": ["purge_email"], "rules": { "purge_email": { "severities": ["high"], "revert_after_minutes": 60 } } } }""", "purge_email has no automatic revert")]
    public void Ceiling_errors_stop_start_up(string json, string expected) =>
        Assert.Contains(expected, Assert.Throws<PolicyException>(() => Policy.Parse(json)).Message);

    [Fact]
    public void Irreversible_kinds_need_the_explicit_opt_in_and_are_warned()
    {
        var p = Policy.Parse("""{ "automation": { "conditional_auto_allowed": ["purge_email"], "irreversible_auto_allowed": ["purge_email"] } }""");
        Assert.Contains(PolicyReport.WarningsFor(p), w => w.Contains("purge_email is in automation.irreversible_auto_allowed"));
        Assert.Contains(PolicyReport.WarningsFor(p), w => w.Contains("purge_email is in automation.conditional_auto_allowed with no rule"));
    }

    [Fact]
    public void Policy_report_shows_conditional_mode_and_the_rule_id()
    {
        var r = PolicyReport.Build(Ceiling());
        var iso = r.Actions.Single(a => a.Kind == "isolate_device");
        Assert.Equal("conditional", iso.Mode);
        Assert.Equal("isolate_device@file", iso.AutoRule);
        Assert.True(iso.Reversible);
        Assert.Contains("automation rule isolate_device@file", r.ToText());
    }

    // ── overrides: ceiling, merge, tighten / loosen ────────────────────────────────────────────

    [Fact]
    public void Override_can_never_exceed_the_file_ceiling()
    {
        var file = Ceiling();
        // Looser mode than the file.
        Assert.Contains(AutomationRules.OverrideProblems("isolate_device", new KindSetting("auto", false, null), file), e => e.Contains("looser than policy.json"));
        // A rule for a kind the ceiling doesn't allow.
        Assert.Contains(AutomationRules.OverrideProblems("revoke_sessions", new KindSetting("approval", false, Rule() with { RevertAfterMinutes = null }), file),
            e => e.Contains("not in automation.conditional_auto_allowed"));
        // Caps beyond the ceiling.
        Assert.Contains(AutomationRules.OverrideProblems("isolate_device", new KindSetting("approval", false, Rule() with { MaxPerHour = 50 }), file), e => e.Contains("max_per_hour"));
        // Dropping a file confirm_target.
        var confirming = file with { ConfirmTarget = ["isolate_device"] };
        Assert.Contains(AutomationRules.OverrideProblems("isolate_device", new KindSetting("approval", false, null), confirming), e => e.Contains("requires confirm_target"));
        // Within the ceiling: fine.
        Assert.Empty(AutomationRules.OverrideProblems("disable_user", new KindSetting("approval", false, Rule() with { RevertAfterMinutes = 30 }), file));
    }

    [Fact]
    public void Effective_policy_is_the_stricter_of_file_and_override_and_ignores_rules_that_no_longer_fit()
    {
        var file = Ceiling();
        // A stored override that claims "auto" for a destructive kind is ignored (the file mode wins).
        var merged = AutomationRules.Merge(file, new Dictionary<string, (KindSetting, long)>
        {
            ["isolate_device"] = (new KindSetting("auto", false, Rule() with { MaxPerHour = 500 }), 4),
            ["disable_user"] = (new KindSetting("approval", false, Rule() with { RevertAfterMinutes = 30 }), 7),
            ["block_indicator"] = (new KindSetting("disabled", false, null), 2),
        }, null);
        Assert.False(merged.AutoApprove.Contains("isolate_device"));
        Assert.False(merged.ActiveRules.ContainsKey("isolate_device")); // the override's rule exceeds the ceiling, so none applies
        Assert.Equal("disable_user@v7", merged.ActiveRules["disable_user"].Id);
        Assert.Contains("block_indicator", merged.Disabled);
        Assert.Same(file, merged.FileCeiling);
    }

    [Fact]
    public void Tightening_and_loosening_are_classified()
    {
        var approval = new KindSetting("approval", false, null);
        Assert.False(AutomationRules.IsLooser(approval, new KindSetting("two_approvers", false, null)));
        Assert.False(AutomationRules.IsLooser(approval, new KindSetting("disabled", false, null)));
        Assert.False(AutomationRules.IsLooser(approval, approval with { ConfirmTarget = true }));
        Assert.True(AutomationRules.IsLooser(new KindSetting("two_approvers", false, null), approval));
        Assert.True(AutomationRules.IsLooser(approval with { ConfirmTarget = true }, approval));
        // Adding a rule is loosening; removing one is tightening.
        Assert.True(AutomationRules.IsLooser(approval, approval with { Rule = Rule() }));
        Assert.False(AutomationRules.IsLooser(approval with { Rule = Rule() }, approval));
        // Rule edits: higher bar or lower caps tighten, lower bar or wider filters loosen.
        Assert.False(AutomationRules.RuleLooser(Rule(), Rule(conf: 0.95)));
        Assert.True(AutomationRules.RuleLooser(Rule(), Rule(conf: 0.85)));
        Assert.False(AutomationRules.RuleLooser(Rule(), Rule() with { MaxPerHour = 1 }));
        Assert.True(AutomationRules.RuleLooser(Rule(), Rule() with { MaxPerHour = 5 }));
        Assert.True(AutomationRules.RuleLooser(Rule(), Rule() with { Severities = ["high", "medium"] }));
        Assert.True(AutomationRules.RuleLooser(Rule(), Rule() with { Sources = null }));
        Assert.True(AutomationRules.RuleLooser(Rule(requesters: ["a"]), Rule()));
        Assert.True(AutomationRules.RuleLooser(Rule(human: true), Rule()));
        Assert.True(AutomationRules.RuleLooser(Rule(revert: 30), Rule(revert: 60)));
        Assert.False(AutomationRules.RuleLooser(Rule(revert: 60), Rule(revert: 30)));
    }

    // ── auto-revert ────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("isolate_device", "release_device")]
    [InlineData("restrict_app_execution", "unrestrict_app_execution")]
    [InlineData("disable_user", "enable_user")]
    [InlineData("block_indicator", "unblock_indicator")]
    public void Reversible_kinds_map_to_their_reverse(string kind, string reverse)
    {
        Assert.True(Reversal.IsReversible(kind));
        Assert.Equal(reverse, Reversal.ReverseKind[kind]);
        Assert.True(Catalog.All.ContainsKey(reverse));
    }

    [Theory]
    [InlineData("disable_service_principal")]
    [InlineData("purge_email")]
    [InlineData("reset_password")]
    [InlineData("revoke_sessions")]
    public void Irreversible_kinds_have_no_revert(string kind) => Assert.False(Reversal.IsReversible(kind));

    [Fact]
    public void Reverse_params_are_built_from_the_original()
    {
        var (k, p, _) = Reversal.Build("isolate_device", new() { ["machine_id"] = Device, ["isolation_type"] = "Full" }, null);
        Assert.Equal("release_device", k);
        Assert.Equal(Device, p!["machine_id"]!.GetValue<string>());
        // The reverse params must pass the reverse kind's own validation.
        Catalog.Get(k!).Validate(JsonSerializer.SerializeToElement(p));

        var (bk, bp, _) = Reversal.Build("block_indicator", new() { ["value"] = "bad.example" }, JsonDocument.Parse("""{ "id": 12345 }""").RootElement);
        Assert.Equal("unblock_indicator", bk);
        Assert.Equal("12345", bp!["indicator_id"]!.GetValue<string>());
        // A dry-run block has no Defender id: nothing to remove, and it says why.
        var (none, _, why) = Reversal.Build("block_indicator", new() { ["value"] = "bad.example" }, JsonDocument.Parse("""{ "dry_run": true }""").RootElement);
        Assert.Null(none);
        Assert.Contains("indicator id is unknown", why);
    }

    [Fact]
    public void Revert_after_is_the_requests_value_capped_by_the_rule()
    {
        var p = Ceiling();
        Assert.Equal(60, PolicyEngine.RevertAfter("isolate_device", p, "isolate_device@file", null));
        Assert.Equal(15, PolicyEngine.RevertAfter("isolate_device", p, "isolate_device@file", 15));
        Assert.Equal(60, PolicyEngine.RevertAfter("isolate_device", p, "isolate_device@file", 600));
        Assert.Equal(600, PolicyEngine.RevertAfter("isolate_device", p, null, 600)); // human-approved: the request decides
        Assert.Null(PolicyEngine.RevertAfter("isolate_device", p, null, null));
        Assert.Null(PolicyEngine.RevertAfter("purge_email", p, null, 60));
    }

    // ── invariants: no agent path to policy administration ─────────────────────────────────────

    [Fact]
    public void Policy_administration_is_never_an_mcp_tool()
    {
        var inputs = new[] { typeof(KindOverrideInput), typeof(TriggerInput), typeof(AutomationPauseInput), typeof(PolicyChangeDecisionInput), typeof(RevertOpInput), typeof(AutoRuleSpec) };
        Assert.DoesNotContain(Tools.All, t => inputs.Contains(t.Input));
        Assert.DoesNotContain(Tools.All, t => t.Name.Contains("policy") || t.Name.Contains("revert") || t.Name.Contains("automation"));
        // No MCP function in BoardTools reaches the policy store's write paths.
        Assert.DoesNotContain(typeof(BoardTools).GetMethods(), m => m.GetCustomAttribute<FunctionAttribute>() is { } f
            && (f.Name.Contains("policy", StringComparison.OrdinalIgnoreCase) || f.Name.Contains("revert", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void Request_action_contract_carries_revert_after_minutes()
    {
        var schema = Contract.SchemaFor<ActionRequest>();
        var prop = schema["properties"]!["revert_after_minutes"]!;
        Assert.Equal(5, prop["minimum"]!.GetValue<long>());
        Assert.Equal(10080, prop["maximum"]!.GetValue<long>());
        Assert.Contains(Tools.All, t => t.Input == typeof(ActionRequest));
    }

    [Fact]
    public void App_only_tokens_never_get_admin_or_approve()
    {
        Assert.DoesNotContain("admin", TokenValidator.MapRoles(["Board.Admin", "Board.Approve", "Board.Post"], "agent"));
        Assert.DoesNotContain("approver", TokenValidator.MapRoles(["Board.Admin", "Board.Approve", "Board.Post"], "agent"));
    }

    [Fact]
    public void Policy_write_routes_require_admin_or_approver_and_are_in_openapi()
    {
        var docs = typeof(PolicyApi).GetMethods().Select(m => (m, d: m.GetCustomAttribute<RouteDocAttribute>())).Where(x => x.d is not null).ToList();
        Assert.NotEmpty(docs);
        foreach (var (m, d) in docs)
        {
            var trigger = m.GetParameters().Select(p => p.GetCustomAttribute<HttpTriggerAttribute>()).OfType<HttpTriggerAttribute>().Single();
            if (trigger.Methods!.Contains("get")) continue;
            Assert.Contains(d!.Role, new[] { Core.Roles.Admin, Core.Roles.Approver });
        }
        var paths = OpenApi.Document()["paths"]!.AsObject();
        Assert.True(paths.ContainsKey("/api/policy/kinds/{kind}"));
        Assert.True(paths.ContainsKey("/api/actions/{id}/revert"));
    }
}
