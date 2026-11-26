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
public sealed record PolicyDecision(Outcome Outcome, IReadOnlyList<string> Notes);
/// <param name="MaliciousIocs">"kind:value" (normalised) of every indicator marked malicious in an ioc message on the incident.</param>
public sealed record IncidentContext(string GraphId, JsonElement Data, IReadOnlySet<string>? MaliciousIocs = null);

/// <summary>
/// What the board would do with a request, before anything is written. The broker's request path, the preview
/// endpoint and the policy simulator all build this the same way (<see cref="PolicyEngine.Assess"/>).
/// </summary>
public sealed record Assessment(string Kind, string Title, bool Destructive, Outcome Outcome, string Status, int ApprovalsRequired,
    bool ConfirmTarget, double ExpiresInHours, IReadOnlyList<string> Notes, string Summary, string Describe);

public static class PolicyEngine
{
    /// <summary>Policy decision plus everything that follows from it (status, approvals, expiry). One code path for request, preview and simulate.</summary>
    public static Assessment Assess(ActionDef def, JsonObject p, IncidentContext? incident, Policy policy)
    {
        var d = Evaluate(def, p, incident, policy);
        var status = d.Outcome switch { Outcome.Reject => "rejected", Outcome.Auto => "approved", _ => "pending_approval" };
        var approvals = d.Outcome == Outcome.NeedsApproval ? policy.ApprovalsFor(def.Kind) : 0;
        var summary = d.Outcome switch
        {
            Outcome.Reject => $"Will be rejected: {d.Notes[0]}",
            Outcome.Auto => "Runs automatically",
            _ when approvals == 2 => "Needs two approvals",
            _ => "Needs approval",
        };
        return new Assessment(def.Kind, def.Title, def.Destructive, d.Outcome, status, approvals,
            d.Outcome == Outcome.NeedsApproval && policy.ConfirmsTarget(def.Kind), policy.ExpiryFor(def.Kind).TotalHours, d.Notes, summary, def.Describe(p));
    }

    /// <summary>
    /// Names an approver may type to confirm the target: every target and every alias the incident evidence gives it
    /// (for a device: MDE id, DNS name and host name). The first is the friendliest to show as the prompt.
    /// </summary>
    public static IReadOnlyList<string> ConfirmNames(ActionDef def, JsonObject p, IncidentContext? incident)
    {
        var targets = def.TargetsOf(p);
        var (users, devices, apps) = Aliases(incident is null ? null : Entities.Extract(incident.Data));
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

    public static PolicyDecision Evaluate(ActionDef def, JsonObject p, IncidentContext? incident, Policy policy)
    {
        var notes = new List<string>();
        if (policy.Disabled.Contains(def.Kind)) return new(Outcome.Reject, [$"{def.Kind} is disabled by policy"]);

        var targets = def.TargetsOf(p);
        var pu = Lower(policy.ProtectedUsers);
        var pd = Lower(policy.ProtectedDevices);
        var pa = Lower(policy.ProtectedApps);
        var pi = Lower(policy.ProtectedIndicators);
        var entities = incident is null ? null : Entities.Extract(incident.Data);
        var (userAliases, deviceAliases, appAliases) = Aliases(entities);

        foreach (var u in targets.Users)
        {
            if (NamesFor(userAliases, u).Any(pu.Contains)) return new(Outcome.Reject, [$"{u} is a protected user"]);
            if (pu.Count > 0 && !userAliases.ContainsKey(u.ToLowerInvariant()) && !u.Contains('@'))
                notes.Add($"{u} could not be matched to a UPN, so the protected-user list was checked by object id only");
        }
        foreach (var d in targets.Devices)
        {
            if (NamesFor(deviceAliases, d).Any(pd.Contains)) return new(Outcome.Reject, [$"{d} is a protected device"]);
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
                var missing = all.Where(t => !keys.Contains(t)).ToList();
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
        var auto = !def.Destructive && policy.AutoApprove.Contains(def.Kind) && !policy.RequireTwoApprovers.Contains(def.Kind) && notes.Count == 0;
        return new(auto ? Outcome.Auto : Outcome.NeedsApproval, notes);
    }

    private static HashSet<string> Lower(IEnumerable<string> xs) => xs.Select(x => x.ToLowerInvariant().TrimEnd('.')).ToHashSet();

    /// <summary>
    /// A value matches when it, or the host it names, equals a protected entry or is a subdomain of one. URLs are
    /// reduced to their host (so https://login.microsoftonline.com/x matches microsoftonline.com) and a trailing dot
    /// is ignored.
    /// </summary>
    internal static bool MatchesProtectedIndicator(string value, IReadOnlySet<string> protectedLower)
    {
        if (protectedLower.Count == 0) return false;
        var v = value.Trim().ToLowerInvariant().TrimEnd('.');
        if (protectedLower.Contains(v)) return true;
        var host = HostOf(v);
        if (host is null) return false;
        foreach (var entry in protectedLower)
        {
            var eh = entry.Contains("://") || entry.Contains('/') ? HostOf(entry) : entry;
            if (eh is not null && (host == eh || host.EndsWith('.' + eh))) return true;
        }
        return false;
    }

    private static string? HostOf(string v)
    {
        var withScheme = v.Contains("://") ? v : "http://" + v;
        if (!Uri.TryCreate(withScheme, UriKind.Absolute, out var u) || u.Host.Length == 0) return null;
        return u.IdnHost.ToLowerInvariant().TrimEnd('.');
    }

    /// <summary>Every name a target is known by in the evidence: device MDE id ↔ DNS name ↔ host name; user oid ↔ UPN; app object id ↔ app id ↔ display name.</summary>
    private static (Dictionary<string, HashSet<string>> Users, Dictionary<string, HashSet<string>> Devices, Dictionary<string, HashSet<string>> Apps) Aliases(IncidentEntities? e)
    {
        var users = new Dictionary<string, HashSet<string>>();
        var devices = new Dictionary<string, HashSet<string>>();
        var apps = new Dictionary<string, HashSet<string>>();
        if (e is null) return (users, devices, apps);
        static void Link(Dictionary<string, HashSet<string>> map, IEnumerable<string?> names)
        {
            var all = names.OfType<string>().Where(n => n.Length > 0).Select(n => n.ToLowerInvariant()).ToList();
            foreach (var n in all)
            {
                if (!map.TryGetValue(n, out var set)) map[n] = set = [];
                set.UnionWith(all);
            }
        }
        foreach (var d in e.Devices) Link(devices, [d.MdeDeviceId, d.Name, d.Name?.Split('.')[0]]);
        foreach (var u in e.Users) Link(users, [u.AadUserId, u.Upn]);
        foreach (var a in e.CloudApps) Link(apps, [a.ObjectId, a.AppId, a.DisplayName]);
        return (users, devices, apps);
    }

    private static IEnumerable<string> NamesFor(Dictionary<string, HashSet<string>> map, string t) =>
        map.TryGetValue(t.ToLowerInvariant(), out var names) ? names : [t.ToLowerInvariant()];
}
