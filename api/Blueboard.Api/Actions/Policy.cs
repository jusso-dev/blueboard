using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;

namespace Blueboard.Api.Actions;

/// <summary>policy.json. Conservative defaults: every destructive action needs a person, protected assets are untouchable.</summary>
public sealed record Policy
{
    public string[] AutoApprove { get; init; } = ["run_av_scan", "collect_investigation_package", "add_incident_comment"];
    public string[] Disabled { get; init; } = [];
    public string[] ProtectedUsers { get; init; } = [];
    public string[] ProtectedDevices { get; init; } = [];
    public string[] ProtectedIndicators { get; init; } = [];
    public bool RequireTargetInIncident { get; init; } = true;

    public static Policy Load(Settings settings)
    {
        if (settings.PolicyFile is not { } path || !File.Exists(path)) return new Policy();
        return JsonSerializer.Deserialize<Policy>(File.ReadAllText(path), Json.Options) ?? new Policy();
    }
}

public enum Outcome { Reject, NeedsApproval, Auto }
public sealed record PolicyDecision(Outcome Outcome, IReadOnlyList<string> Notes);
/// <param name="MaliciousIocs">"kind:value" (normalised) of every indicator marked malicious in an ioc message on the incident.</param>
public sealed record IncidentContext(string GraphId, JsonElement Data, IReadOnlySet<string>? MaliciousIocs = null);

public static class PolicyEngine
{
    public static PolicyDecision Evaluate(ActionDef def, JsonObject p, IncidentContext? incident, Policy policy)
    {
        var notes = new List<string>();
        if (policy.Disabled.Contains(def.Kind)) return new(Outcome.Reject, [$"{def.Kind} is disabled by policy"]);

        var targets = def.TargetsOf(p);
        var pu = Lower(policy.ProtectedUsers);
        var pd = Lower(policy.ProtectedDevices);
        var pi = Lower(policy.ProtectedIndicators);
        var entities = incident is null ? null : Entities.Extract(incident.Data);
        var (userAliases, deviceAliases) = Aliases(entities);

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
        foreach (var o in targets.Other)
        {
            var v = o.ToLowerInvariant();
            if (pi.Contains(v) || pi.Any(x => v.EndsWith('.' + x) || v.Contains("://" + x)))
                return new(Outcome.Reject, [$"{o} matches a protected indicator"]);
        }

        var all = targets.All.ToList();
        if (all.Count > 0)
        {
            if (incident is null) notes.Add("not linked to an incident: targets cannot be checked against evidence");
            else if (policy.RequireTargetInIncident)
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

        // Destructive kinds always wait for a person, whatever auto_approve says.
        var auto = !def.Destructive && policy.AutoApprove.Contains(def.Kind) && notes.Count == 0;
        return new(auto ? Outcome.Auto : Outcome.NeedsApproval, notes);
    }

    private static HashSet<string> Lower(IEnumerable<string> xs) => xs.Select(x => x.ToLowerInvariant()).ToHashSet();

    /// <summary>Every name a target is known by in the evidence: device MDE id ↔ DNS name ↔ host name; user oid ↔ UPN.</summary>
    private static (Dictionary<string, HashSet<string>> Users, Dictionary<string, HashSet<string>> Devices) Aliases(IncidentEntities? e)
    {
        var users = new Dictionary<string, HashSet<string>>();
        var devices = new Dictionary<string, HashSet<string>>();
        if (e is null) return (users, devices);
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
        return (users, devices);
    }

    private static IEnumerable<string> NamesFor(Dictionary<string, HashSet<string>> map, string t) =>
        map.TryGetValue(t.ToLowerInvariant(), out var names) ? names : [t.ToLowerInvariant()];
}
