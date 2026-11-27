namespace Blueboard.Api.Actions;

/// <summary>How one action kind is treated by a policy, in plain words.</summary>
public sealed record ActionMode(string Kind, string Title, string Target, bool Destructive, string Mode, string Words, bool ConfirmTarget, double ExpiryHours,
    string? AutoRule = null, bool Reversible = false);

public sealed record ProtectedCounts(int Users, int Devices, int Indicators, int Apps = 0);

/// <summary>Protected values. Only Board.Admin sees these; everyone else gets counts.</summary>
public sealed record ProtectedLists(string[] Users, string[] Devices, string[] Indicators, string[]? Apps = null);

public sealed record LimitRow(string Bucket, string Agent, string Human);

/// <summary>
/// The effective policy as a table plus warnings. One source for <c>blueboard policy-check</c>, GET /api/policy and the
/// /policy page, so they can't disagree.
/// </summary>
public sealed record PolicyReport(
    int Version, IReadOnlyList<ActionMode> Actions, ProtectedCounts Protected, bool RequireTargetInIncident,
    IReadOnlyList<LimitRow> Limits, int PendingActionsPerIncident, IReadOnlyList<string> Warnings, ProtectedLists? Lists = null)
{
    /// <summary>The mode with conditional rules shown: "conditional" when a rule in force can let the kind run on its own.</summary>
    public static string DisplayModeOf(string kind, Policy p)
    {
        var mode = ModeOf(kind, p);
        return mode is "approval" or "on_instruction" && p.ActiveRules.ContainsKey(kind) ? "conditional" : mode;
    }

    public static string ModeOf(string kind, Policy p)
    {
        var def = Catalog.Get(kind);
        if (p.Disabled.Contains(kind)) return "disabled";
        if (p.RequireTwoApprovers.Contains(kind)) return "two_approvers";
        if (!def.Destructive && p.AutoApprove.Contains(kind)) return "auto";
        // confirm_target wins: a person has to type the target, so an instruction in chat isn't enough.
        return p.ActOnInstruction.Contains(kind) && !p.ConfirmsTarget(kind) ? "on_instruction" : "approval";
    }

    private static string Words(string mode) => mode switch
    {
        "disabled" => "Off: every request is rejected",
        "two_approvers" => "Needs two different human approvers",
        "auto" => "Runs on its own when every target is in the incident evidence; otherwise needs approval",
        "on_instruction" => "Needs a human approver; an approver telling an agent to do it on the board counts as the approval",
        "conditional" => "Runs on its own only when its automation rule's conditions all hold; otherwise needs a human approver",
        _ => "Needs a human approver",
    };

    public static PolicyReport Build(Policy p, bool includeLists = false)
    {
        var actions = Catalog.All.Values.Select(d =>
        {
            var mode = DisplayModeOf(d.Kind, p);
            var rule = p.ActiveRules.GetValueOrDefault(d.Kind);
            return new ActionMode(d.Kind, d.Title, Catalog.TargetType(d.Kind), d.Destructive, mode,
                rule is null ? Words(mode) : $"{Words(mode)}. Rule {rule.Id}: {AutomationRules.Describe(rule.Spec)}",
                mode != "disabled" && p.ConfirmsTarget(d.Kind), p.ExpiryFor(d.Kind).TotalHours, rule?.Id, Reversal.IsReversible(d.Kind));
        }).ToList();
        var limits = Blueboard.Api.Actions.Limits.Buckets.Select(b => new LimitRow(b, p.Limits.For("agent", b).ToString(), p.Limits.For("human", b).ToString())).ToList();
        return new PolicyReport(p.Version, actions, new(p.ProtectedUsers.Length, p.ProtectedDevices.Length, p.ProtectedIndicators.Length, p.ProtectedApps.Length),
            p.RequireTargetInIncident, limits, p.Limits.PendingActionsPerIncident, WarningsFor(p),
            includeLists ? new ProtectedLists(p.ProtectedUsers, p.ProtectedDevices, p.ProtectedIndicators, p.ProtectedApps) : null);
    }

    /// <summary>Things that are allowed but probably not what you meant.</summary>
    public static IReadOnlyList<string> WarningsFor(Policy p)
    {
        var w = new List<string>();
        foreach (var k in p.AutoApprove.Where(k => Catalog.All.TryGetValue(k, out var d) && d.Destructive))
            w.Add($"{k} is in auto_approve but is destructive, so it is ignored: it always needs a human approver");
        foreach (var k in p.AutoApprove.Where(p.RequireTwoApprovers.Contains))
            w.Add($"{k} is in both auto_approve and require_two_approvers: it needs two approvers");
        foreach (var k in p.ActOnInstruction.Where(p.ConfirmTarget.Contains))
            w.Add($"{k} is in both act_on_instruction and confirm_target: an approver must type the target, so instructions in chat are refused for it");
        foreach (var k in p.ActOnInstruction.Where(k => Catalog.All.TryGetValue(k, out var d) && !d.Destructive && p.AutoApprove.Contains(k)))
            w.Add($"{k} is in both act_on_instruction and auto_approve: it already runs on its own when the evidence matches");
        foreach (var k in p.Disabled.Where(k => p.AutoApprove.Contains(k) || p.RequireTwoApprovers.Contains(k) || p.ConfirmTarget.Contains(k) || p.ActOnInstruction.Contains(k)))
            w.Add($"{k} is disabled, so its other settings have no effect");
        if (p.ProtectedUsers.Length == 0) w.Add("protected_users is empty: list break-glass and Global Admin accounts");
        if (p.ProtectedDevices.Length == 0) w.Add("protected_devices is empty: list domain controllers and other critical servers");
        if (p.ProtectedIndicators.Length == 0) w.Add("protected_indicators is empty: list your own domains and Microsoft update hosts");
        if (!p.Disabled.Contains("disable_service_principal") && p.ProtectedApps.Length == 0)
            w.Add("protected_apps is empty: list blueboard's own app registration and critical enterprise apps");
        if (!p.RequireTargetInIncident) w.Add("require_target_in_incident is off: targets outside the incident evidence are not flagged");
        var a = p.Automation;
        foreach (var k in a.IrreversibleAutoAllowed.Where(k => a.ConditionalAutoAllowed.Contains(k)))
            w.Add($"{k} is in automation.irreversible_auto_allowed: once it runs on its own it can't be undone automatically");
        foreach (var k in a.IrreversibleAutoAllowed.Where(k => !a.ConditionalAutoAllowed.Contains(k)))
            w.Add($"{k} is in automation.irreversible_auto_allowed but not in automation.conditional_auto_allowed, so it has no effect");
        foreach (var k in a.ConditionalAutoAllowed.Where(k => !a.Rules.ContainsKey(k)))
            w.Add($"{k} is in automation.conditional_auto_allowed with no rule in the file: it waits for a person until two admins agree a rule on /policy");
        foreach (var (k, r) in a.Rules.Where(kv => kv.Value.MinConfidence < 0.9))
            w.Add($"automation.rules.{k}.min_confidence is {r.MinConfidence}: a lower bar makes prompt-injected verdicts more dangerous");
        foreach (var (k, _) in a.Rules.Where(kv => kv.Value.Requesters is not { Length: > 0 } && !kv.Value.RequireHumanVerdict))
            w.Add($"automation.rules.{k} accepts any requester and an agent's verdict: consider requesters or require_human_verdict");
        if (p.ExpiryHours > 24) w.Add($"expiry_hours is {p.ExpiryHours}: approvals of requests older than a shift may act on stale evidence");
        foreach (var (k, h) in p.ExpiryHoursByKind.Where(kv => kv.Value > 24))
            w.Add($"expiry_hours_by_kind.{k} is {h}: approvals of requests older than a shift may act on stale evidence");
        return w;
    }

    /// <summary>Fixed-width text for the CLI.</summary>
    public string ToText()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"policy version {Version}");
        sb.AppendLine();
        var kw = Actions.Max(a => a.Kind.Length) + 2;
        sb.AppendLine($"{"action".PadRight(kw)}{"target".PadRight(11)}{"mode".PadRight(15)}{"confirm".PadRight(9)}expiry");
        foreach (var a in Actions)
            sb.AppendLine($"{a.Kind.PadRight(kw)}{a.Target.PadRight(11)}{a.Mode.PadRight(15)}{(a.ConfirmTarget ? "yes" : "").PadRight(9)}{a.ExpiryHours:0.##} h");
        sb.AppendLine();
        sb.AppendLine($"protected: {Protected.Users} users, {Protected.Devices} devices, {Protected.Indicators} indicators, {Protected.Apps} apps");
        sb.AppendLine($"require_target_in_incident: {(RequireTargetInIncident ? "on" : "off")}");
        sb.AppendLine($"pending actions per incident: {PendingActionsPerIncident}");
        foreach (var a in Actions.Where(a => a.AutoRule is not null)) sb.AppendLine($"automation rule {a.AutoRule}: {a.Words}");
        sb.AppendLine("rate limits (agent / human):");
        foreach (var l in Limits) sb.AppendLine($"  {l.Bucket.PadRight(16)}{l.Agent.PadRight(16)}{l.Human}");
        if (Warnings.Count > 0)
        {
            sb.AppendLine();
            foreach (var w in Warnings) sb.AppendLine($"warning: {w}");
        }
        return sb.ToString();
    }
}
