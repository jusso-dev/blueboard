using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Blueboard.Contracts;

namespace Blueboard.Api.Actions;

/// <summary>
/// policy.json "automation": the ceiling for conditional automation. Nothing an admin sets on /policy can go past it.
/// Defaults are empty, so a policy without this section behaves exactly as before (every destructive kind waits for
/// a person). See docs/POLICY.md, "Conditional automation".
/// </summary>
public sealed record AutomationPolicy
{
    /// <summary>Destructive kinds that may EVER run on their own under a rule. Empty: none.</summary>
    public string[] ConditionalAutoAllowed { get; init; } = [];
    /// <summary>Explicit opt-in for kinds with no automatic revert (purge_email, reset_password, revoke_sessions...).</summary>
    public string[] IrreversibleAutoAllowed { get; init; } = [];
    /// <summary>Rules in force when no admin override exists for the kind.</summary>
    public Dictionary<string, AutoRuleSpec> Rules { get; init; } = [];
    /// <summary>No rule may accept a corroborating verdict below this confidence.</summary>
    public double MinConfidenceFloor { get; init; } = 0.8;
    /// <summary>Highest max_per_hour any rule may set.</summary>
    public int MaxPerHour { get; init; } = 10;
    /// <summary>Highest max_per_incident any rule may set.</summary>
    public int MaxPerIncident { get; init; } = 3;
    /// <summary>Longest revert_after_minutes any rule (or request) may set.</summary>
    public int MaxRevertAfterMinutes { get; init; } = 1440;
    /// <summary>How long a loosening change waits for a second admin before it expires.</summary>
    public double ChangeExpiryHours { get; init; } = 24;

    public IEnumerable<string> Validate(Policy p)
    {
        if (MinConfidenceFloor is < 0.5 or > 1) yield return "automation.min_confidence_floor must be 0.5–1";
        if (MaxPerHour is < 1 or > 1000) yield return "automation.max_per_hour must be 1–1000";
        if (MaxPerIncident is < 1 or > 100) yield return "automation.max_per_incident must be 1–100";
        if (MaxRevertAfterMinutes is < 5 or > 10080) yield return "automation.max_revert_after_minutes must be 5–10080";
        if (ChangeExpiryHours is < 1 or > 168) yield return "automation.change_expiry_hours must be 1–168";
        foreach (var (key, kinds) in new[] { ("conditional_auto_allowed", ConditionalAutoAllowed), ("irreversible_auto_allowed", IrreversibleAutoAllowed) })
            foreach (var k in kinds.Where(k => !Catalog.All.ContainsKey(k)))
                yield return $"automation.{key}: unknown action kind {k}";
        foreach (var k in ConditionalAutoAllowed.Where(Catalog.All.ContainsKey))
        {
            if (Catalog.NeverAuto.Contains(k))
                yield return $"automation.conditional_auto_allowed: {k} always needs a human approver and can never run on its own";
            else if (!Catalog.All[k].Destructive)
                yield return $"automation.conditional_auto_allowed: {k} is not destructive; use auto_approve for it";
            else if (!Reversal.IsReversible(k) && !IrreversibleAutoAllowed.Contains(k))
                yield return $"automation.conditional_auto_allowed: {k} has no automatic revert, so it must also be listed in automation.irreversible_auto_allowed";
            if (p.RequireTwoApprovers.Contains(k))
                yield return $"automation.conditional_auto_allowed: {k} is in require_two_approvers; a two-person kind never runs on its own";
        }
        foreach (var (k, rule) in Rules)
        {
            if (!Catalog.All.ContainsKey(k)) { yield return $"automation.rules: unknown action kind {k}"; continue; }
            foreach (var why in AutomationRules.Problems(k, rule, p)) yield return $"automation.rules.{k}: {why}";
        }
    }
}

/// <summary>A rule in force for one kind. Id is what the board shows ("isolate_device@file", "isolate_device@v12").</summary>
public sealed record ActiveRule(string Id, AutoRuleSpec Spec);

/// <summary>A verdict message on the incident, as the board read it (the newest one per author).</summary>
public sealed record VerdictFact(string Author, string AuthorKind, string Classification, double Confidence);

/// <summary>
/// What a conditional rule needs besides the request and the incident: who is asking, the verdicts on the incident and
/// how many times the kind already ran on its own. The broker loads these from the database; tests build them by hand.
/// </summary>
/// <param name="RequesterRisk">
/// The requester's agent risk score (0-100) from <c>IAgentRiskSource</c>, loaded only when the rule sets
/// max_requester_risk. Null means unknown (a person, an agent not scored yet, or no risk source), which fails that
/// condition: an unscored requester never counts as low risk.
/// </param>
public sealed record AutomationFacts(string Requester, IReadOnlyList<VerdictFact> Verdicts, int RunsLastHour, int RunsOnIncident, int? RequesterRisk = null);

/// <summary>Everything an admin can set for one action kind. Mode is one of <see cref="PolicyModes.Order"/>.</summary>
public sealed record KindSetting(string Mode, bool ConfirmTarget, AutoRuleSpec? Rule);

/// <summary>
/// The automatic undo for reversible kinds. A kind with no entry (or whose reverse kind is not in the catalogue) is
/// irreversible: it may only run on its own when policy.json lists it in automation.irreversible_auto_allowed.
/// disable_service_principal is irreversible here because the catalogue has no enable_service_principal; so are
/// okta_clear_user_sessions, okta_reset_factors, purge_email and intune_expedite_quality_update (nothing undoes them).
/// Only the containing direction is listed: undoing a recovery (release → isolate again) is never automatic.
/// </summary>
public static class Reversal
{
    public static readonly IReadOnlyDictionary<string, string> ReverseKind = BuildMap();

    private static Dictionary<string, string> BuildMap()
    {
        var map = new Dictionary<string, string>
        {
            ["isolate_device"] = "release_device",
            ["restrict_app_execution"] = "unrestrict_app_execution",
            ["disable_user"] = "enable_user",
            ["block_indicator"] = "unblock_indicator",
            // A board-created detection rule is undone by disabling it (the rule is kept, it stops raising alerts).
            ["create_detection_rule"] = "disable_detection_rule",
        };
        // Connector inverses (okta_suspend_user → okta_unsuspend_user), without the recovery direction.
        foreach (var (k, v) in Catalog.ConnectorReverseKinds)
            if (Catalog.All.TryGetValue(k, out var def) && def.Stage != "recover") map.TryAdd(k, v);
        return map;
    }

    public static bool IsReversible(string kind) => ReverseKind.TryGetValue(kind, out var r) && Catalog.All.ContainsKey(r);

    /// <summary>
    /// Params for the reverse action, from the original's params, its result (block_indicator) or its id
    /// (create_detection_rule), or why it can't be built. A block that only ran as a dry run has no Defender indicator
    /// id to remove.
    /// </summary>
    public static (string? Kind, JsonObject? Params, string? Why) Build(string kind, JsonObject p, JsonElement? result, Guid? actionId = null)
    {
        if (!IsReversible(kind)) return (null, null, $"{kind} has no automatic revert");
        var reverse = ReverseKind[kind];
        switch (kind)
        {
            case "isolate_device":
            case "restrict_app_execution":
                return (reverse, new JsonObject { ["machine_id"] = p["machine_id"]!.GetValue<string>() }, null);
            case "disable_user":
            case "okta_suspend_user":
                return (reverse, new JsonObject { ["user"] = p["user"]!.GetValue<string>() }, null);
            case "block_indicator":
                if (result is { ValueKind: JsonValueKind.Object } r && r.TryGetProperty("id", out var id)
                    && (id.ValueKind == JsonValueKind.Number ? id.GetRawText() : id.ValueKind == JsonValueKind.String ? id.GetString() : null) is { } v
                    && v.Length is > 0 and <= 20 && v.All(char.IsAsciiDigit))
                    return (reverse, new JsonObject { ["indicator_id"] = v }, null);
                return (null, null, "the block's Defender indicator id is unknown (it ran as a dry run, or Defender didn't return one), so there is nothing to remove");
            case "create_detection_rule":
                // The rule's id is derived from the creating action's id (Catalog.RuleId), so the action id is enough.
                return actionId is { } aid
                    ? (reverse, new JsonObject { ["rule_action_id"] = aid.ToString() }, null)
                    : (null, null, "the creating action's id is needed to find the rule to disable");
            default:
                return (null, null, $"{kind} has no automatic revert");
        }
    }
}

/// <summary>Action modes from loosest to strictest. An admin override may only make a kind stricter than policy.json.</summary>
public static class PolicyModes
{
    public static readonly string[] Order = ["auto", "on_instruction", "approval", "two_approvers", "disabled"];
    public static int Strictness(string mode) => Array.IndexOf(Order, mode) is var i and >= 0 ? i : throw new BoardException($"unknown mode {mode}");
    public static string Stricter(string a, string b) => Strictness(a) >= Strictness(b) ? a : b;
}

/// <summary>Conditional automation: rule validation against the ceiling, the conditions themselves, and tighten/loosen.</summary>
public static partial class AutomationRules
{
    public static readonly string[] Severities = ["informational", "low", "medium", "high"];
    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,63}$")] private static partial Regex Handle();

    /// <summary>Why a rule for this kind exceeds the policy.json ceiling, or is malformed. Empty when it is allowed.</summary>
    public static IEnumerable<string> Problems(string kind, AutoRuleSpec r, Policy file)
    {
        var c = file.Automation;
        var def = Catalog.All.GetValueOrDefault(kind);
        if (def is null) { yield return $"unknown action kind {kind}"; yield break; }
        if (Catalog.NeverAuto.Contains(kind)) { yield return $"{kind} always needs a human approver and can never run on its own"; yield break; }
        if (!def.Destructive) yield return $"{kind} is not destructive; use auto_approve for it";
        if (!c.ConditionalAutoAllowed.Contains(kind)) yield return $"{kind} is not in automation.conditional_auto_allowed in policy.json";
        if (!Reversal.IsReversible(kind) && !c.IrreversibleAutoAllowed.Contains(kind))
            yield return $"{kind} has no automatic revert and is not in automation.irreversible_auto_allowed";
        if (file.Disabled.Contains(kind)) yield return $"{kind} is disabled in policy.json";
        if (file.RequireTwoApprovers.Contains(kind)) yield return $"{kind} needs two approvers in policy.json";
        if (r.MinConfidence < c.MinConfidenceFloor || r.MinConfidence > 1)
            yield return $"min_confidence must be {c.MinConfidenceFloor}–1 (automation.min_confidence_floor)";
        if (r.Severities is not { Length: > 0 } sev || sev.Any(s => !Severities.Contains(s)))
            yield return $"severities must list at least one of {string.Join(", ", Severities)}";
        if (r.Sources is { } src && (src.Length > 20 || src.Any(s => s is not { Length: > 0 and <= 200 })))
            yield return "sources: up to 20 entries of 1–200 characters";
        if (r.MaxPerHour < 1 || r.MaxPerHour > c.MaxPerHour) yield return $"max_per_hour must be 1–{c.MaxPerHour} (automation.max_per_hour)";
        if (r.MaxPerIncident < 1 || r.MaxPerIncident > c.MaxPerIncident) yield return $"max_per_incident must be 1–{c.MaxPerIncident} (automation.max_per_incident)";
        if (r.Requesters is { } req && (req.Length > 50 || req.Any(h => h is null || !Handle().IsMatch(h))))
            yield return "requesters: up to 50 board handles";
        if (r.MaxRequesterRisk is < 0 or > 100) yield return "max_requester_risk must be 0–100";
        if (Reversal.IsReversible(kind))
        {
            if (r.RevertAfterMinutes is not { } m) yield return $"revert_after_minutes is required: {kind} is reversible, so an automatic run must undo itself";
            else if (m < 5 || m > c.MaxRevertAfterMinutes) yield return $"revert_after_minutes must be 5–{c.MaxRevertAfterMinutes} (automation.max_revert_after_minutes)";
        }
        else if (r.RevertAfterMinutes is not null) yield return $"revert_after_minutes: {kind} has no automatic revert";
    }

    /// <summary>
    /// Conditions that fail for this request, in words. Empty: every condition holds and the kind may run on its own.
    /// The requester's own verdicts never count: board content is attacker-influenced, and an agent vouching for its
    /// own request is no corroboration at all.
    /// </summary>
    public static List<string> Unmet(ActionDef def, JsonObject p, IncidentContext? incident, AutoRuleSpec rule, AutomationFacts? facts)
    {
        var why = new List<string>();
        if (incident is null) { why.Add("the request is not linked to an incident"); return why; }
        if (facts is null) { why.Add("automation facts were not loaded"); return why; }
        if (rule.Requesters is { Length: > 0 } allowed && !allowed.Contains(facts.Requester, StringComparer.OrdinalIgnoreCase))
            why.Add($"@{facts.Requester} is not an allowed requester for this rule");

        var severity = Str(incident.Data, "severity")?.ToLowerInvariant();
        if (severity is null || rule.Severities?.Contains(severity, StringComparer.OrdinalIgnoreCase) != true)
            why.Add($"incident severity {severity ?? "unknown"} is not one of {string.Join(", ", rule.Severities ?? [])}");

        if (rule.Sources is { Length: > 0 } sources)
        {
            var seen = Sources(incident.Data);
            if (!sources.Any(s => seen.Contains(s, StringComparer.OrdinalIgnoreCase)))
                why.Add($"no alert from {string.Join(", ", sources)} on the incident");
        }

        // Always mandatory for automation, whatever require_target_in_incident says.
        var keys = Entities.Extract(incident.Data).Keys();
        var missing = def.TargetsOf(p).All.Where(t => !keys.Contains(t)).ToList();
        if (missing.Count > 0) why.Add($"not every target is in the incident evidence ({string.Join(", ", missing)})");

        var others = facts.Verdicts.Where(v => !v.Author.Equals(facts.Requester, StringComparison.OrdinalIgnoreCase)).ToList();
        var counted = rule.RequireHumanVerdict ? others.Where(v => v.AuthorKind == "human").ToList() : others;
        var dissent = others.Where(v => v.Classification is "falsePositive" or "informationalExpectedActivity").ToList();
        if (dissent.Count > 0)
            why.Add($"verdicts disagree: {string.Join(", ", dissent.Select(v => $"@{v.Author} says {v.Classification}"))}");
        else if (!counted.Any(v => v.Classification == "truePositive" && v.Confidence >= rule.MinConfidence))
            why.Add($"no truePositive verdict with confidence ≥ {rule.MinConfidence:0.##} from {(rule.RequireHumanVerdict ? "a person" : "a principal")} other than @{facts.Requester}");

        if (rule.MaxRequesterRisk is { } maxRisk)
        {
            if (facts.RequesterRisk is not { } risk)
                why.Add($"@{facts.Requester} has no agent risk score (unknown is never treated as low; the rule needs ≤ {maxRisk})");
            else if (risk > maxRisk)
                why.Add($"@{facts.Requester}'s agent risk score is {risk}, above the rule's max_requester_risk {maxRisk}");
        }

        if (facts.RunsLastHour >= rule.MaxPerHour)
            why.Add($"cap reached: {def.Kind} already ran on its own {facts.RunsLastHour} time(s) in the last hour (max {rule.MaxPerHour})");
        if (facts.RunsOnIncident >= rule.MaxPerIncident)
            why.Add($"cap reached: {def.Kind} already ran on its own {facts.RunsOnIncident} time(s) on incident {incident.GraphId} (max {rule.MaxPerIncident})");
        return why;
    }

    /// <summary>Plain words for a rule (/policy, simulator notes).</summary>
    public static string Describe(AutoRuleSpec r) =>
        $"runs on its own when a {(r.RequireHumanVerdict ? "person" : "principal")} other than the requester posted a truePositive verdict with confidence ≥ {r.MinConfidence:0.##}, "
        + $"severity is {string.Join("/", r.Severities ?? [])}"
        + (r.Sources is { Length: > 0 } s ? $", an alert came from {string.Join("/", s)}" : "")
        + (r.Requesters is { Length: > 0 } q ? $", the requester is @{string.Join("/@", q)}" : "")
        + (r.MaxRequesterRisk is { } mr ? $", the requester's agent risk score is known and ≤ {mr}" : "")
        + $", every target is in the evidence, and it ran on its own fewer than {r.MaxPerHour} times this hour and {r.MaxPerIncident} on the incident"
        + (r.RevertAfterMinutes is { } m ? $"; undone automatically after {m} min" : "; irreversible");

    private static List<string> Sources(JsonElement incident)
    {
        var list = new List<string>();
        if (incident.ValueKind == JsonValueKind.Object && incident.TryGetProperty("alerts", out var alerts) && alerts.ValueKind == JsonValueKind.Array)
            foreach (var a in alerts.EnumerateArray())
                foreach (var k in new[] { "serviceSource", "detectionSource", "productName" })
                    if (Str(a, k) is { } v) list.Add(v);
        return list;
    }

    private static string? Str(JsonElement e, string k) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    // ── tighten / loosen ───────────────────────────────────────────────────────────────────────

    /// <summary>True when <paramref name="after"/> lets anything run with less human involvement than <paramref name="before"/>.</summary>
    public static bool IsLooser(KindSetting before, KindSetting after) =>
        PolicyModes.Strictness(after.Mode) < PolicyModes.Strictness(before.Mode)
        || (before.ConfirmTarget && !after.ConfirmTarget)
        || RuleLooser(before.Rule, after.Rule);

    public static bool RuleLooser(AutoRuleSpec? a, AutoRuleSpec? b)
    {
        if (b is null) return false;
        if (a is null) return true;
        static bool Wider(string[]? from, string[]? to) =>
            from is { Length: > 0 } f && (to is not { Length: > 0 } t || t.Any(x => !f.Contains(x, StringComparer.OrdinalIgnoreCase)));
        return b.MinConfidence < a.MinConfidence
               || (b.Severities ?? []).Any(s => !(a.Severities ?? []).Contains(s, StringComparer.OrdinalIgnoreCase))
               || Wider(a.Sources, b.Sources)
               || Wider(a.Requesters, b.Requesters)
               || b.MaxPerHour > a.MaxPerHour
               || b.MaxPerIncident > a.MaxPerIncident
               || (b.RevertAfterMinutes ?? 0) > (a.RevertAfterMinutes ?? 0)
               || (a.RequireHumanVerdict && !b.RequireHumanVerdict)
               || (a.MaxRequesterRisk is { } ar && (b.MaxRequesterRisk is not { } br || br > ar));
    }

    public static bool Same(KindSetting a, KindSetting b) =>
        a.Mode == b.Mode && a.ConfirmTarget == b.ConfirmTarget && JsonSerializer.Serialize(a.Rule, Json.Options) == JsonSerializer.Serialize(b.Rule, Json.Options);

    // ── file setting, override validation, merge ───────────────────────────────────────────────

    /// <summary>What policy.json alone says for a kind (its rule only when it fits the ceiling).</summary>
    public static KindSetting FileSetting(string kind, Policy file) =>
        new(PolicyReport.ModeOf(kind, file), file.ConfirmsTarget(kind),
            file.Automation.Rules.TryGetValue(kind, out var r) && !Problems(kind, r, file).Any() ? r : null);

    /// <summary>Why an admin override for this kind would exceed policy.json, or is inconsistent. Empty when allowed.</summary>
    public static List<string> OverrideProblems(string kind, KindSetting s, Policy file)
    {
        var errors = new List<string>();
        if (!Catalog.All.TryGetValue(kind, out var def)) { errors.Add($"unknown action kind {kind}"); return errors; }
        if (!PolicyModes.Order.Contains(s.Mode)) { errors.Add($"unknown mode {s.Mode}"); return errors; }
        var fileMode = PolicyReport.ModeOf(kind, file);
        if (PolicyModes.Strictness(s.Mode) < PolicyModes.Strictness(fileMode))
            errors.Add($"mode {s.Mode} is looser than policy.json allows for {kind} ({fileMode})");
        if (s.Mode == "auto" && def.Destructive) errors.Add($"{kind} is destructive: it can't be auto; use a conditional rule if policy.json allows one");
        if (file.ConfirmsTarget(kind) && !s.ConfirmTarget) errors.Add($"policy.json requires confirm_target for {kind}");
        if (s.Mode == "on_instruction" && s.ConfirmTarget) errors.Add("on_instruction can't be combined with confirm_target: a person has to type the target");
        if (s.Rule is { } r)
        {
            if (s.Mode is not ("approval" or "on_instruction")) errors.Add($"a conditional rule needs mode approval or on_instruction (not {s.Mode})");
            errors.AddRange(Problems(kind, r, file));
        }
        return errors;
    }

    /// <summary>File ∩ override: each setting takes the stricter of the two, and a rule only counts while it fits the ceiling.</summary>
    public static KindSetting Effective(string kind, Policy file, KindSetting? over)
    {
        var f = FileSetting(kind, file);
        if (over is null) return f with { Rule = RuleAllowed(f.Mode) ? f.Rule : null };
        var mode = PolicyModes.Order.Contains(over.Mode) ? PolicyModes.Stricter(f.Mode, over.Mode) : f.Mode;
        var rule = over.Rule is { } r && !Problems(kind, r, file).Any() && RuleAllowed(mode) ? r : null;
        var confirm = f.ConfirmTarget || over.ConfirmTarget;
        if (mode == "on_instruction" && confirm) mode = "approval";
        return new KindSetting(mode, confirm, rule);
    }

    private static bool RuleAllowed(string mode) => mode is "approval" or "on_instruction";

    /// <summary>
    /// The effective policy: policy.json with each kind's effective setting written back into the lists the engine
    /// reads, the rules in force, and the automation pause. Protected lists, limits and expiry are file-only.
    /// </summary>
    public static Policy Merge(Policy file, IReadOnlyDictionary<string, (KindSetting Setting, long Version)> overrides, AutomationPause? pause)
    {
        var disabled = file.Disabled.ToHashSet();
        var two = file.RequireTwoApprovers.ToHashSet();
        var auto = file.AutoApprove.ToHashSet();
        var instr = file.ActOnInstruction.ToHashSet();
        var confirm = file.ConfirmTarget.ToHashSet();
        var rules = new Dictionary<string, ActiveRule>();
        foreach (var kind in Catalog.All.Keys)
        {
            overrides.TryGetValue(kind, out var o);
            var e = Effective(kind, file, o.Setting);
            if (e.Rule is { } r) rules[kind] = new ActiveRule(o.Setting is null ? $"{kind}@file" : $"{kind}@v{o.Version}", r);
            if (o.Setting is null) continue;
            Set(disabled, kind, e.Mode == "disabled");
            Set(two, kind, e.Mode == "two_approvers");
            Set(auto, kind, e.Mode == "auto");
            Set(instr, kind, e.Mode == "on_instruction");
            Set(confirm, kind, e.ConfirmTarget);
        }
        return file with
        {
            Disabled = [.. disabled.Order(StringComparer.Ordinal)],
            RequireTwoApprovers = [.. two.Order(StringComparer.Ordinal)],
            AutoApprove = [.. auto.Order(StringComparer.Ordinal)],
            ActOnInstruction = [.. instr.Order(StringComparer.Ordinal)],
            ConfirmTarget = [.. confirm.Order(StringComparer.Ordinal)],
            ActiveRules = rules,
            Pause = pause is { Paused: true } ? pause : null,
            FileCeiling = file.FileCeiling ?? file,
        };
    }

    private static void Set(HashSet<string> s, string k, bool on)
    {
        if (on) s.Add(k);
        else s.Remove(k);
    }
}

/// <summary>The automation kill switch: while paused, every automatic decision becomes a request for approval.</summary>
public sealed record AutomationPause(bool Paused, string? By = null, DateTimeOffset? At = null, string? Reason = null);
