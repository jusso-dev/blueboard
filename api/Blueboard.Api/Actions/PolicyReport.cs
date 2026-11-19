namespace Blueboard.Api.Actions;

/// <summary>How one action kind is treated by a policy, in plain words.</summary>
public sealed record ActionMode(string Kind, string Title, string Target, bool Destructive, string Mode, string Words, bool ConfirmTarget, double ExpiryHours);

public sealed record ProtectedCounts(int Users, int Devices, int Indicators);

/// <summary>Protected values. Only Board.Admin sees these; everyone else gets counts.</summary>
public sealed record ProtectedLists(string[] Users, string[] Devices, string[] Indicators);

public sealed record LimitRow(string Bucket, string Agent, string Human);

/// <summary>
/// The effective policy as a table plus warnings. One source for <c>blueboard policy-check</c>, GET /api/policy and the
/// /policy page, so they can't disagree.
/// </summary>
public sealed record PolicyReport(
    int Version, IReadOnlyList<ActionMode> Actions, ProtectedCounts Protected, bool RequireTargetInIncident,
    IReadOnlyList<LimitRow> Limits, int PendingActionsPerIncident, IReadOnlyList<string> Warnings, ProtectedLists? Lists = null)
{
    public static string ModeOf(string kind, Policy p)
    {
        var def = Catalog.Get(kind);
        if (p.Disabled.Contains(kind)) return "disabled";
        if (p.RequireTwoApprovers.Contains(kind)) return "two_approvers";
        return !def.Destructive && p.AutoApprove.Contains(kind) ? "auto" : "approval";
    }

    private static string Words(string mode) => mode switch
    {
        "disabled" => "Off: every request is rejected",
        "two_approvers" => "Needs two different human approvers",
        "auto" => "Runs on its own when every target is in the incident evidence; otherwise needs approval",
        _ => "Needs a human approver",
    };

    public static PolicyReport Build(Policy p, bool includeLists = false)
    {
        var actions = Catalog.All.Values.Select(d =>
        {
            var mode = ModeOf(d.Kind, p);
            return new ActionMode(d.Kind, d.Title, Catalog.TargetType(d.Kind), d.Destructive, mode, Words(mode),
                mode != "disabled" && p.ConfirmsTarget(d.Kind), p.ExpiryFor(d.Kind).TotalHours);
        }).ToList();
        var limits = Blueboard.Api.Actions.Limits.Buckets.Select(b => new LimitRow(b, p.Limits.For("agent", b).ToString(), p.Limits.For("human", b).ToString())).ToList();
        return new PolicyReport(p.Version, actions, new(p.ProtectedUsers.Length, p.ProtectedDevices.Length, p.ProtectedIndicators.Length),
            p.RequireTargetInIncident, limits, p.Limits.PendingActionsPerIncident, WarningsFor(p),
            includeLists ? new ProtectedLists(p.ProtectedUsers, p.ProtectedDevices, p.ProtectedIndicators) : null);
    }

    /// <summary>Things that are allowed but probably not what you meant.</summary>
    public static IReadOnlyList<string> WarningsFor(Policy p)
    {
        var w = new List<string>();
        foreach (var k in p.AutoApprove.Where(k => Catalog.All.TryGetValue(k, out var d) && d.Destructive))
            w.Add($"{k} is in auto_approve but is destructive, so it is ignored: it always needs a human approver");
        foreach (var k in p.AutoApprove.Where(p.RequireTwoApprovers.Contains))
            w.Add($"{k} is in both auto_approve and require_two_approvers: it needs two approvers");
        foreach (var k in p.Disabled.Where(k => p.AutoApprove.Contains(k) || p.RequireTwoApprovers.Contains(k) || p.ConfirmTarget.Contains(k)))
            w.Add($"{k} is disabled, so its other settings have no effect");
        if (p.ProtectedUsers.Length == 0) w.Add("protected_users is empty: list break-glass and Global Admin accounts");
        if (p.ProtectedDevices.Length == 0) w.Add("protected_devices is empty: list domain controllers and other critical servers");
        if (p.ProtectedIndicators.Length == 0) w.Add("protected_indicators is empty: list your own domains and Microsoft update hosts");
        if (!p.RequireTargetInIncident) w.Add("require_target_in_incident is off: targets outside the incident evidence are not flagged");
        if (p.ExpiryHours > 24) w.Add($"expiry_hours is {p.ExpiryHours}: approvals of requests older than a shift may act on stale evidence");
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
        sb.AppendLine($"protected: {Protected.Users} users, {Protected.Devices} devices, {Protected.Indicators} indicators");
        sb.AppendLine($"require_target_in_incident: {(RequireTargetInIncident ? "on" : "off")}");
        sb.AppendLine($"pending actions per incident: {PendingActionsPerIncident}");
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
