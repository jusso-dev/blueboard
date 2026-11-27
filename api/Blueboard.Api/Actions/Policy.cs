using Blueboard.Contracts;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;

namespace Blueboard.Api.Actions;

/// <summary>
/// policy.json. Conservative defaults: every destructive action needs a person, protected assets are untouchable.
/// Parsing is strict: an unknown key (a typo such as <c>auto_aprove</c>) or an unknown action kind fails start-up
/// instead of being silently dropped. See docs/POLICY.md.
/// </summary>
public sealed record Policy
{
    public const int CurrentVersion = 1;

    public int Version { get; init; } = CurrentVersion;
    public string[] AutoApprove { get; init; } = ["run_av_scan", "collect_investigation_package", "add_incident_comment"];
    public string[] Disabled { get; init; } = [];
    public string[] ProtectedUsers { get; init; } = [];
    public string[] ProtectedDevices { get; init; } = [];
    public string[] ProtectedIndicators { get; init; } = [];
    public string[] ProtectedApps { get; init; } = [];
    public bool RequireTargetInIncident { get; init; } = true;
    /// <summary>Kinds that need two different human approvers. The first approval moves the action to approved_once.</summary>
    public string[] RequireTwoApprovers { get; init; } = [];
    /// <summary>Kinds whose approver must type the target back (a device name, UPN or indicator) to stop click-through approvals.</summary>
    public string[] ConfirmTarget { get; init; } = [];
    /// <summary>
    /// Kinds an agent may file on a human approver's instruction (request_action on_behalf_of = their board message):
    /// the instruction counts as that person's approval. Never kinds in require_two_approvers; kinds also in
    /// confirm_target are refused at request time (a person has to type the target).
    /// </summary>
    public string[] ActOnInstruction { get; init; } = [];
    /// <summary>A pending request older than this can't be approved; the recovery timer marks it expired.</summary>
    public double ExpiryHours { get; init; } = 4;
    public Dictionary<string, double> ExpiryHoursByKind { get; init; } = [];
    public Limits Limits { get; init; } = new();
    /// <summary>Ceiling for conditional automation of destructive kinds (docs/POLICY.md). Empty by default: nothing destructive runs on its own.</summary>
    public AutomationPolicy Automation { get; init; } = new();

    private readonly IReadOnlyDictionary<string, ActiveRule>? _rules;
    /// <summary>
    /// Conditional rules in force, by kind. For a policy read from a file: the file's rules that fit its ceiling
    /// (computed on each read, so a <c>with</c> copy never carries a stale set). For the effective policy
    /// (<see cref="AutomationRules.Merge"/>): file ∩ admin overrides, set explicitly. Not a policy key.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyDictionary<string, ActiveRule> ActiveRules
    {
        get => _rules ?? (Automation.Rules.Count == 0 ? NoRules : Catalog.All.Keys
            .Select(k => (k, r: AutomationRules.Effective(k, this, null).Rule))
            .Where(x => x.r is not null).ToDictionary(x => x.k, x => new ActiveRule($"{x.k}@file", x.r!)));
        init => _rules = value;
    }
    private static readonly IReadOnlyDictionary<string, ActiveRule> NoRules = new Dictionary<string, ActiveRule>();
    /// <summary>Set while an admin has paused automation: every automatic decision becomes a request for approval. Not a policy key.</summary>
    [JsonIgnore] public AutomationPause? Pause { get; init; }
    /// <summary>The policy.json this effective policy was built from (the ceiling for overrides). Not a policy key.</summary>
    [JsonIgnore] public Policy? FileCeiling { get; init; }

    public TimeSpan ExpiryFor(string kind) => TimeSpan.FromHours(ExpiryHoursByKind.TryGetValue(kind, out var h) ? h : ExpiryHours);
    public int ApprovalsFor(string kind) => RequireTwoApprovers.Contains(kind) ? 2 : 1;
    public bool ConfirmsTarget(string kind) => ConfirmTarget.Contains(kind);

    private static readonly JsonSerializerOptions Strict = new(Json.Options) { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };

    /// <summary>Loads BLUEBOARD_POLICY_FILE. No file configured means the built-in defaults; a configured file that is missing or invalid throws.</summary>
    /// <summary>Where this policy was loaded from (setup page), or null for the built-in default. Not a policy key.</summary>
    [JsonIgnore] public string? Source { get; init; }
    /// <summary>Always false: a configured policy that is missing stops start-up (kept for the setup page's wording).</summary>
    [JsonIgnore] public bool Missing => false;

    public static Policy Load(Settings settings) =>
        settings.PolicyFile is { } path ? LoadFile(path) with { Source = settings.PolicySource ?? path }
        : settings.PolicyJson is { } json ? Parse(json, settings.PolicySource ?? "BLUEBOARD_POLICY_JSON") with { Source = settings.PolicySource ?? "app setting BLUEBOARD_POLICY_JSON" }
        : new Policy();

    public static Policy LoadFile(string path)
    {
        if (!File.Exists(path)) throw new PolicyException($"policy file {path} not found");
        return Parse(File.ReadAllText(path), path);
    }

    public static Policy Parse(string json, string source = "policy")
    {
        Policy policy;
        try
        {
            policy = JsonSerializer.Deserialize<Policy>(json, Strict) ?? throw new PolicyException($"{source}: empty policy");
        }
        catch (JsonException ex)
        {
            var at = ex.Path is { Length: > 2 } path ? path[2..] : "the top level";
            throw new PolicyException(ex.Message.Contains("could not be mapped")
                ? $"{source}: unknown key {at} (check the spelling; see docs/POLICY.md for every key)"
                : $"{source}: invalid value at {at}: {ex.Message.Split(" Path:")[0]}");
        }
        var errors = policy.Validate();
        if (errors.Count > 0) throw new PolicyException($"{source}: " + string.Join("; ", errors));
        return policy;
    }

    /// <summary>Errors that make a policy unusable (as opposed to warnings, see PolicyReport).</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (Version != CurrentVersion) errors.Add($"version must be {CurrentVersion} (got {Version})");
        foreach (var (key, kinds) in new[] { ("auto_approve", AutoApprove), ("disabled", Disabled), ("require_two_approvers", RequireTwoApprovers), ("confirm_target", ConfirmTarget), ("act_on_instruction", ActOnInstruction) })
            foreach (var k in kinds.Where(k => !Catalog.All.ContainsKey(k)))
                errors.Add($"{key}: unknown action kind {k}");
        // One person's chat message can't stand in for two people's approvals.
        foreach (var k in ActOnInstruction.Where(RequireTwoApprovers.Contains))
            errors.Add($"act_on_instruction: {k} is in require_two_approvers, which needs two approvers, so a single person's instruction can't approve it");
        foreach (var k in ExpiryHoursByKind.Keys.Where(k => !Catalog.All.ContainsKey(k)))
            errors.Add($"expiry_hours_by_kind: unknown action kind {k}");
        foreach (var (k, h) in ExpiryHoursByKind.Append(new("default", ExpiryHours)))
            if (h is not (> 0 and <= 720)) errors.Add($"expiry hours for {k} must be more than 0 and at most 720");
        errors.AddRange(Limits.Validate());
        errors.AddRange(Automation.Validate(this));
        return errors;
    }
}

public sealed class PolicyException(string message) : Exception(message);

/// <summary>One token bucket: up to <c>Capacity</c> calls, refilled evenly over <c>PerSeconds</c>.</summary>
public sealed record RateLimit
{
    public int Capacity { get; init; }
    public int PerSeconds { get; init; }
    public RateLimit() { }
    public RateLimit(int capacity, int perSeconds) => (Capacity, PerSeconds) = (capacity, perSeconds);
    public double RefillPerSecond => (double)Capacity / PerSeconds;
    public override string ToString() => $"{Capacity} per {(PerSeconds % 60 == 0 ? $"{PerSeconds / 60} min" : $"{PerSeconds} s")}";
}

/// <summary>Per-principal limits for one kind of principal. Unset buckets fall back to that kind's defaults.</summary>
public sealed record LimitSet
{
    public RateLimit? Post { get; init; }
    public RateLimit? Hunt { get; init; }
    public RateLimit? Lookup { get; init; }
    public RateLimit? ActionRequest { get; init; }
    public RateLimit? Claim { get; init; }
}

/// <summary>Rate limits (issue #5). Agents get tighter defaults than people; the board's system principal is never limited.</summary>
public sealed record Limits
{
    public static readonly string[] Buckets = ["post", "hunt", "lookup", "action_request", "claim"];

    private static readonly LimitSet AgentDefaults = new()
    {
        Post = new(60, 60), Hunt = new(10, 60), Lookup = new(30, 60), ActionRequest = new(5, 600), Claim = new(60, 60),
    };
    private static readonly LimitSet HumanDefaults = new()
    {
        Post = new(120, 60), Hunt = new(30, 60), Lookup = new(120, 60), ActionRequest = new(30, 600), Claim = new(120, 60),
    };

    public LimitSet Agent { get; init; } = new();
    public LimitSet Human { get; init; } = new();
    /// <summary>Most actions waiting for approval (pending or 1 of 2) on one incident.</summary>
    public int PendingActionsPerIncident { get; init; } = 10;

    public RateLimit For(string principalKind, string bucket)
    {
        var (set, defaults) = principalKind == "human" ? (Human, HumanDefaults) : (Agent, AgentDefaults);
        return Pick(set, bucket) ?? Pick(defaults, bucket)!;
    }

    private static RateLimit? Pick(LimitSet s, string bucket) => bucket switch
    {
        "post" => s.Post, "hunt" => s.Hunt, "lookup" => s.Lookup, "action_request" => s.ActionRequest, "claim" => s.Claim,
        _ => throw new ArgumentOutOfRangeException(nameof(bucket), bucket, "unknown rate limit bucket"),
    };

    public IEnumerable<string> Validate()
    {
        if (PendingActionsPerIncident is < 1 or > 1000) yield return "limits.pending_actions_per_incident must be 1–1000";
        foreach (var (kind, set) in new[] { ("agent", Agent), ("human", Human) })
            foreach (var b in Buckets)
                if (Pick(set, b) is { } l && (l.Capacity is < 1 or > 100_000 || l.PerSeconds is < 1 or > 86_400))
                    yield return $"limits.{kind}.{b}: capacity must be 1–100000 and per_seconds 1–86400";
    }
}

public enum Outcome { Reject, NeedsApproval, Auto }
/// <param name="AutoRule">Set when a destructive kind runs on its own under a conditional automation rule (its id).</param>
public sealed record PolicyDecision(Outcome Outcome, IReadOnlyList<string> Notes, string? AutoRule = null);
/// <param name="MaliciousIocs">"kind:value" (normalised) of every indicator marked malicious in an ioc message on the incident.</param>
/// <param name="IdentityLinks">
/// Outside-IdP identities (Okta) that share a name with someone in the evidence or the request: each is every name one
/// outside user is known by (id, login, emails). PolicyEngine links them to the Entra aliases (UPN ↔ object id).
/// </param>
public sealed record IncidentContext(string GraphId, JsonElement Data, IReadOnlySet<string>? MaliciousIocs = null,
    IReadOnlyList<IReadOnlyList<string>>? IdentityLinks = null);

/// <summary>
/// What the board would do with a request, before anything is written. The broker's request path, the preview
/// endpoint and the policy simulator all build this the same way (<see cref="PolicyEngine.Assess"/>).
/// </summary>
public sealed record Assessment(string Kind, string Title, bool Destructive, Outcome Outcome, string Status, int ApprovalsRequired,
    bool ConfirmTarget, double ExpiresInHours, IReadOnlyList<string> Notes, string Summary, string Describe,
    string? AutoRule = null, int? RevertAfterMinutes = null);

public static class PolicyEngine
{
    /// <summary>Policy decision plus everything that follows from it (status, approvals, expiry). One code path for request, preview and simulate.</summary>
    /// <param name="automationFacts">Verdicts and auto-run counts for conditional rules (WS1); null when the kind has no rule in force.</param>
    /// <param name="revertAfterMinutes">The request's own revert_after_minutes, if any.</param>
    /// <param name="actionFacts">What the kind's resolver looked up (Resolvers.cs): device aliases, back-test binding, rule to disable.</param>
    public static Assessment Assess(ActionDef def, JsonObject p, IncidentContext? incident, Policy policy, AutomationFacts? automationFacts = null, int? revertAfterMinutes = null,
        ActionFacts? actionFacts = null)
    {
        var d = Evaluate(def, p, incident, policy, automationFacts, actionFacts);
        var status = d.Outcome switch { Outcome.Reject => "rejected", Outcome.Auto => "approved", _ => "pending_approval" };
        var approvals = d.Outcome == Outcome.NeedsApproval ? policy.ApprovalsFor(def.Kind) : 0;
        var summary = d.Outcome switch
        {
            Outcome.Reject => $"Will be rejected: {d.Notes[0]}",
            Outcome.Auto when d.AutoRule is not null => $"Runs automatically under rule {d.AutoRule}",
            Outcome.Auto => "Runs automatically",
            _ when approvals == 2 => "Needs two approvals",
            _ => "Needs approval",
        };
        return new Assessment(def.Kind, def.Title, def.Destructive, d.Outcome, status, approvals,
            d.Outcome == Outcome.NeedsApproval && policy.ConfirmsTarget(def.Kind), policy.ExpiryFor(def.Kind).TotalHours, d.Notes, summary, def.Describe(p),
            d.AutoRule, d.Outcome == Outcome.Reject ? null : RevertAfter(def.Kind, policy, d.AutoRule, revertAfterMinutes));
    }

    /// <summary>
    /// Minutes after success at which the board undoes the action: the request's own value, capped by the rule's when it
    /// ran under one (an automatic run always reverts). Null when nothing is scheduled.
    /// </summary>
    public static int? RevertAfter(string kind, Policy policy, string? autoRule, int? requested)
    {
        if (!Reversal.IsReversible(kind)) return null;
        var rule = autoRule is not null && policy.ActiveRules.TryGetValue(kind, out var r) ? r.Spec.RevertAfterMinutes : null;
        return (rule, requested) switch
        {
            ({ } a, { } b) => Math.Min(a, b),
            ({ } a, null) => a,
            (null, var b) => b,
        };
    }

    /// <summary>
    /// Names an approver may type to confirm the target: every target and every alias the incident evidence gives it
    /// (for a device: MDE id, DNS name and host name). The first is the friendliest to show as the prompt.
    /// </summary>
    public static IReadOnlyList<string> ConfirmNames(ActionDef def, JsonObject p, IncidentContext? incident, ActionFacts? actionFacts = null)
    {
        var targets = def.TargetsOf(p);
        var (users, devices, apps) = Aliases(incident is null ? null : Entities.Extract(incident.Data), incident?.IdentityLinks, actionFacts);
        var names = new List<string>();
        foreach (var d in targets.Devices)
        {
            var aliases = NamesFor(devices, d).ToList();
            names.AddRange(aliases.Where(a => a.Contains('.')).Concat(aliases.Where(a => !a.Contains('.') && a != d.ToLowerInvariant())).Append(d));
        }
        foreach (var u in targets.Users) names.AddRange(NamesFor(users, u).OrderByDescending(n => n.Contains('@')).Append(u));
        foreach (var a in targets.AppList) names.AddRange(NamesFor(apps, a).OrderByDescending(n => !Guid.TryParse(n, out _)).Append(a));
        names.AddRange(targets.Other);
        if (names.Count == 0 && p["incident_id"] is { } inc) names.Add(inc.GetValue<string>());
        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// The one policy decision for request, preview, simulate, approval, run-now and execution. Two kinds of looked-up
    /// facts feed it: <paramref name="automationFacts"/> (verdicts and auto-run counts, only for conditional rules) and
    /// <paramref name="actionFacts"/> (the kind's own resolver: device aliases, back-test binding, the rule a disable
    /// refers to).
    /// </summary>
    public static PolicyDecision Evaluate(ActionDef def, JsonObject p, IncidentContext? incident, Policy policy,
        AutomationFacts? automationFacts = null, ActionFacts? actionFacts = null)
    {
        var notes = new List<string>();
        if (policy.Disabled.Contains(def.Kind)) return new(Outcome.Reject, [$"{def.Kind} is disabled by policy"]);
        // A kind's own precondition (Resolvers.cs), e.g. create_detection_rule's back-test binding.
        if (actionFacts?.Reject is { } refused) return new(Outcome.Reject, [refused]);

        var targets = def.TargetsOf(p);
        var pu = Lower(policy.ProtectedUsers);
        var pd = Lower(policy.ProtectedDevices);
        var pa = Lower(policy.ProtectedApps);
        var pi = Lower(policy.ProtectedIndicators);
        var entities = incident is null ? null : Entities.Extract(incident.Data);
        var (userAliases, deviceAliases, appAliases) = Aliases(entities, incident?.IdentityLinks, actionFacts);

        foreach (var u in targets.Users)
        {
            if (NamesFor(userAliases, u).Any(pu.Contains)) return new(Outcome.Reject, [$"{u} is a protected user"]);
            if (pu.Count > 0 && !userAliases.ContainsKey(u.ToLowerInvariant()) && !u.Contains('@'))
                notes.Add($"{u} could not be matched to a UPN, so the protected-user list was checked by object id only");
        }
        // Okta kinds (cross-IdP): the Okta identity links that resolve an Okta id to its login and emails (and so to a
        // protected UPN) are loaded with the incident, so these kinds must be linked to one (fail closed).
        if (Catalog.OktaKinds.Contains(def.Kind) && incident is null)
            return new(Outcome.Reject, [$"{def.Kind} must be linked to an incident so the Okta user can be checked against protected users"]);
        foreach (var d in targets.Devices)
        {
            if (NamesFor(deviceAliases, d).Any(pd.Contains)) return new(Outcome.Reject, [$"{d} is a protected device"]);
            // Intune reports short device names (dc01) while protected lists usually hold FQDNs: for names the board
            // resolved itself, a protected FQDN also matches by its host label. This only ever adds rejections.
            if (actionFacts?.DeviceAliases?.ContainsKey(d.ToLowerInvariant()) == true && NamesFor(deviceAliases, d).Any(n => !n.Contains('.') && pd.Any(x => x.Split('.')[0] == n)))
                return new(Outcome.Reject, [$"{d} is a protected device (matched by host name)"]);
            if (actionFacts?.UnresolvedDevices?.Contains(d, StringComparer.OrdinalIgnoreCase) == true)
            {
                notes.Add($"{d} could not be resolved to its other device names, so the protected-device list was checked by id only");
                continue;
            }
            if (pd.Count > 0 && !deviceAliases.ContainsKey(d.ToLowerInvariant()))
                notes.Add($"{d} is not in the incident evidence, so its host name is unknown and the protected-device list was checked by id only");
        }
        foreach (var a in targets.AppList)
        {
            if (NamesFor(appAliases, a).Any(pa.Contains)) return new(Outcome.Reject, [$"{a} is a protected application / service principal"]);
            if (pa.Count > 0 && !appAliases.ContainsKey(a.ToLowerInvariant()))
                notes.Add($"{a} is not in the incident evidence, so its app id and display name are unknown and the protected-app list was checked by object id only");
        }
        foreach (var o in targets.Other)
            if (MatchesProtectedIndicator(o, pi)) return new(Outcome.Reject, [$"{o} matches a protected indicator"]);

        var all = targets.All.ToList();
        if (all.Count > 0 || def.Kind == "unblock_indicator")
        {
            if (incident is null) notes.Add("not linked to an incident: targets cannot be checked against evidence");
            else if (policy.RequireTargetInIncident && all.Count > 0)
            {
                var keys = entities!.Keys();
                // A target counts as in the evidence under any of its names: an Okta id whose login or email is a UPN
                // in evidence, or an Intune device id whose MDE id is in the alert.
                var missing = all.Where(t => !keys.Contains(t)
                    && !(Catalog.OktaKinds.Contains(def.Kind) && NamesFor(userAliases, t).Any(keys.Contains))
                    && !(targets.Devices.Contains(t) && NamesFor(deviceAliases, t).Any(keys.Contains))).ToList();
                if (missing.Count > 0) notes.Add($"not in incident {incident.GraphId} evidence: {string.Join(", ", missing)}");
            }
        }

        if (Catalog.IncidentScoped.Contains(def.Kind))
        {
            var id = p["incident_id"]!.GetValue<string>();
            if (incident is null) return new(Outcome.Reject, [$"{def.Kind} must be linked to the incident it changes"]);
            if (incident.GraphId != id) return new(Outcome.Reject, [$"incident_id {id} does not match linked incident {incident.GraphId}"]);
        }

        if (Catalog.NeedsMaliciousIoc.Contains(def.Kind))
        {
            if (incident is null) return new(Outcome.Reject, [$"{def.Kind} must be linked to the incident where the indicator was confirmed"]);
            var key = $"{p["kind"]!.GetValue<string>()}:{p["value"]!.GetValue<string>()}";
            if (incident.MaliciousIocs?.Contains(key) != true)
                return new(Outcome.Reject, [$"{p["value"]} is not marked malicious in an ioc message on incident {incident.GraphId}"]);
        }

        // Destructive kinds always wait for a person, whatever auto_approve says; two-approver kinds never run on their own.
        // The resolver's notes (back-test volumes, resolved update) are for the approver; they don't block automation.
        var resolverNotes = actionFacts?.Notes ?? [];
        // NeverAuto kinds (create_detection_rule) always wait for a person: not via auto_approve, not via a rule.
        if (Catalog.NeverAuto.Contains(def.Kind)) return new(Outcome.NeedsApproval, [.. notes, .. resolverNotes]);
        var auto = !def.Destructive && policy.AutoApprove.Contains(def.Kind) && !policy.RequireTwoApprovers.Contains(def.Kind) && notes.Count == 0;
        if (auto && policy.Pause is { Paused: true } pause)
            return new(Outcome.NeedsApproval, [PausedNote(pause), .. resolverNotes]);
        if (auto) return new(Outcome.Auto, [.. notes, .. resolverNotes]);

        // Conditional automation: a destructive kind may run on its own only under a rule in force (within the
        // policy.json ceiling) and only when every condition holds. Anything short of that is the normal approval path.
        if (def.Destructive && policy.ActiveRules.TryGetValue(def.Kind, out var rule) && !policy.RequireTwoApprovers.Contains(def.Kind) && !policy.Disabled.Contains(def.Kind))
        {
            if (policy.Pause is { Paused: true } paused) return new(Outcome.NeedsApproval, [.. notes, PausedNote(paused), .. resolverNotes]);
            var unmet = AutomationRules.Unmet(def, p, incident, rule.Spec, automationFacts);
            if (notes.Count > 0) unmet.Insert(0, "the policy notes above need a person to look");
            if (unmet.Count == 0) return new(Outcome.Auto, [.. notes, .. resolverNotes], rule.Id);
            return new(Outcome.NeedsApproval, [.. notes, .. unmet.Select(u => $"automation rule {rule.Id} not applied: {u}"), .. resolverNotes]);
        }
        return new(Outcome.NeedsApproval, [.. notes, .. resolverNotes]);
    }

    private static string PausedNote(AutomationPause p) =>
        $"automation is paused{(p.By is null ? "" : $" by @{p.By}")}, so this waits for a person{(p.Reason is { Length: > 0 } r ? $" ({r})" : "")}";

    private static HashSet<string> Lower(IEnumerable<string> xs) => xs.Select(x => x.ToLowerInvariant().TrimEnd('.')).ToHashSet();

    /// <summary>
    /// A value matches when it, or the host it names, equals a protected entry or is a subdomain of one. URLs are
    /// reduced to their host (so https://login.microsoftonline.com/x matches microsoftonline.com), IP addresses are
    /// canonicalised (so uncompressed IPv6 and IPv4-mapped IPv6 cannot bypass a protected IP), and a trailing dot
    /// is ignored.
    /// </summary>
    internal static bool MatchesProtectedIndicator(string value, IReadOnlySet<string> protectedLower)
    {
        if (protectedLower.Count == 0) return false;
        var v = value.Trim().ToLowerInvariant().TrimEnd('.');
        if (protectedLower.Contains(v)) return true;
        var canonicalValueIp = CanonicalIp(v);
        var host = HostOf(v);
        var canonicalHostIp = host is null ? null : CanonicalIp(host);
        foreach (var entry in protectedLower)
        {
            var entryIp = CanonicalIp(entry);
            if (entryIp is not null && (entryIp == canonicalValueIp || entryIp == canonicalHostIp)) return true;
            var eh = entry.Contains("://") || entry.Contains('/') ? HostOf(entry) : entry.Trim('[', ']');
            if (eh is null) continue;
            var ehIp = CanonicalIp(eh);
            if (ehIp is not null && (ehIp == canonicalValueIp || ehIp == canonicalHostIp)) return true;
            if (host is not null && (host == eh || host.EndsWith('.' + eh))) return true;
        }
        return false;
    }

    private static string? CanonicalIp(string raw)
    {
        var stripped = raw.Trim().Trim('[', ']');
        if (!System.Net.IPAddress.TryParse(stripped, out var ip)) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }

    private static string? HostOf(string v)
    {
        var withScheme = v.Contains("://") ? v : (v.Contains(':') && System.Net.IPAddress.TryParse(v.Trim('[', ']'), out _) ? $"http://[{v.Trim('[', ']')}]" : "http://" + v);
        if (!Uri.TryCreate(withScheme, UriKind.Absolute, out var u) || u.Host.Length == 0) return null;
        return u.IdnHost.Trim('[', ']').ToLowerInvariant().TrimEnd('.');
    }

    /// <summary>
    /// Every name a target is known by: names the board resolved itself for this action (Intune managed device id ↔
    /// Entra device id ↔ MDE id ↔ name), then the evidence's: device MDE id ↔ DNS name ↔ host name; user oid ↔ UPN; app
    /// object id ↔ app id ↔ display name. Outside-IdP identities (Okta id ↔ login ↔ emails) are merged into the user
    /// groups transitively, so an Okta user whose login or email equals an Entra UPN shares that UPN's object id too.
    /// </summary>
    private static (Dictionary<string, HashSet<string>> Users, Dictionary<string, HashSet<string>> Devices, Dictionary<string, HashSet<string>> Apps) Aliases(
        IncidentEntities? e, IReadOnlyList<IReadOnlyList<string>>? identityLinks = null, ActionFacts? facts = null)
    {
        var users = new Dictionary<string, HashSet<string>>();
        var devices = new Dictionary<string, HashSet<string>>();
        var apps = new Dictionary<string, HashSet<string>>();
        // Names the board looked up itself (Intune managed device id ↔ Entra device id ↔ MDE id ↔ name), then the evidence's.
        foreach (var (target, names) in facts?.DeviceAliases ?? new Dictionary<string, string[]>()) Link(devices, [target, .. names]);
        static void Link(Dictionary<string, HashSet<string>> map, IEnumerable<string?> names)
        {
            var all = names.OfType<string>().Where(n => n.Length > 0).Select(n => n.ToLowerInvariant()).ToList();
            foreach (var n in all)
            {
                if (!map.TryGetValue(n, out var set)) map[n] = set = [];
                set.UnionWith(all);
            }
        }
        // Outside identities merge with every group a name already belongs to, so links chain
        // (Okta id ↔ email = UPN ↔ Entra oid) and every member sees the whole group.
        static void Merge(Dictionary<string, HashSet<string>> map, IEnumerable<string?> names)
        {
            var merged = names.OfType<string>().Where(n => n.Length > 0).Select(n => n.ToLowerInvariant()).ToHashSet();
            foreach (var n in merged.ToList()) if (map.TryGetValue(n, out var existing)) merged.UnionWith(existing);
            foreach (var n in merged) map[n] = merged;
        }
        if (e is not null)
        {
            foreach (var d in e.Devices)
            {
                // Linking unions alias sets, so an MDE id the resolver tied to an Intune id picks up the evidence's names too.
                var known = new[] { d.MdeDeviceId, d.Name }.OfType<string>().SelectMany(n => devices.TryGetValue(n.ToLowerInvariant(), out var s) ? s : []).ToList();
                Link(devices, [d.MdeDeviceId, d.Name, d.Name?.Split('.')[0], .. known]);
            }
            foreach (var u in e.Users) Link(users, [u.AadUserId, u.Upn]);
            foreach (var a in e.CloudApps) Link(apps, [a.ObjectId, a.AppId, a.DisplayName]);
        }
        foreach (var names in identityLinks ?? []) Merge(users, names);
        return (users, devices, apps);
    }

    /// <summary>The user aliases (lower case) the policy check would use for <paramref name="target"/>. For tests and the preview.</summary>
    internal static IReadOnlyCollection<string> UserAliases(string target, IncidentContext? incident) =>
        NamesFor(Aliases(incident is null ? null : Entities.Extract(incident.Data), incident?.IdentityLinks).Users, target).ToHashSet();

    private static IEnumerable<string> NamesFor(Dictionary<string, HashSet<string>> map, string t) =>
        map.TryGetValue(t.ToLowerInvariant(), out var names) ? names : [t.ToLowerInvariant()];
}
