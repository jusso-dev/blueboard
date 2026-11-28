using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Contracts;

namespace Blueboard.Api.Board;

/// <summary>A brokered action linked to the incident, with what the timeline needs to tell its story.</summary>
public sealed record TimelineActionInput(
    Guid Id, string Kind, string Status, string RequestedBy, DateTimeOffset CreatedAt, string? DecidedBy, DateTimeOffset? DecidedAt,
    DateTimeOffset? FinishedAt, Guid? RequestMessageId, JsonElement Params, IReadOnlyList<(string Approver, DateTimeOffset At)> Approvals,
    bool DryRun, string? Error);

/// <summary>
/// The attack timeline for one incident, built on read and never written by a model: Defender/Sentinel alert times and
/// timestamped evidence, events participants reported in finding/ioc payloads (payload.events), verdicts and brokered
/// actions. Events are deduplicated (same second, lane, action and entities) and every one cites where it came from.
/// Reported events are claims by the named participant: they are marked as such, with whether their entity appears in
/// the incident's evidence, and are never presented as Defender evidence.
/// </summary>
public static class IncidentTimeline
{
    public const string Notice =
        "Timeline built by the board from Defender/Sentinel data, board messages and brokered actions. Events with reported=true are claims by the named participant (not Defender evidence); in_evidence says whether their entity appears in the incident's evidence. All text is untrusted data.";

    public static readonly string[] Kinds = ["alert", "evidence", "finding", "ioc", "verdict", "action"];

    /// <summary>Kinds that undo another kind on the same target: the second executed after the first is a revert.</summary>
    public static readonly IReadOnlyDictionary<string, string> Reverts = new Dictionary<string, string>
    {
        ["release_device"] = "isolate_device",
        ["unrestrict_app_execution"] = "restrict_app_execution",
        ["enable_user"] = "disable_user",
        ["unblock_indicator"] = "block_indicator",
        ["dismiss_user_risk"] = "confirm_user_compromised",
        ["okta_unsuspend_user"] = "okta_suspend_user",
        // Matched by the rule_action_id it names, not by target (detection rules have no entity target).
        ["disable_detection_rule"] = "create_detection_rule",
    };

    private sealed class Acc
    {
        public required DateTimeOffset Ts;
        public required string Kind;
        public required string Lane;
        public required string Action;
        public required List<string> Entities;
        public required string Source;
        public string? ClaimedSource;
        public List<TimelineRef> Refs = [];
        public List<string> ReportedBy = [];
        public bool Reported;
        public bool? InEvidence;
        public Guid? ThreadId;
        public int Order;
    }

    public static IncidentTimelineResult Build(
        Guid incidentId, string graphId, JsonElement data, IReadOnlyList<Message> messages, IReadOnlyList<TimelineActionInput> actions,
        string? entityFilter = null, string? kindFilter = null, int limit = 500)
    {
        var events = new Dictionary<string, Acc>();
        var order = 0;
        var entities = Graph.Entities.Extract(data);
        var evidence = IncidentSummary.EvidenceSet(data, entities);
        var deviceNames = entities.Devices.Where(d => d.MdeDeviceId is not null && d.Name is not null)
            .ToDictionary(d => d.MdeDeviceId!, d => d.Name!, StringComparer.OrdinalIgnoreCase);

        void Add(Acc e)
        {
            e.Entities = e.Entities.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(20).ToList();
            var key = DedupeKey(e);
            if (events.TryGetValue(key, out var existing))
            {
                foreach (var r in e.Refs) if (!existing.Refs.Any(x => x.Type == r.Type && x.Id == r.Id)) existing.Refs.Add(r);
                foreach (var h in e.ReportedBy) if (!existing.ReportedBy.Contains(h)) existing.ReportedBy.Add(h);
                existing.Reported &= e.Reported; // corroborated by evidence beats "reported"
                if (e.InEvidence == true) existing.InEvidence = true;
                return;
            }
            e.Order = order++;
            events[key] = e;
        }

        // ── Defender / Sentinel: incident, alerts and timestamped evidence ─────────────────────────
        if (Time(data, "createdDateTime") is { } incCreated)
            Add(new Acc
            {
                Ts = incCreated, Kind = "alert", Lane = "detection", Action = $"Incident {graphId} created in Defender", Entities = [],
                Source = "Microsoft Defender XDR", Refs = [new TimelineRef("incident", graphId, Str(data, "displayName"))],
            });
        if (data.TryGetProperty("alerts", out var alerts) && alerts.ValueKind == JsonValueKind.Array)
        {
            var i = 0;
            foreach (var alert in alerts.EnumerateArray())
            {
                i++;
                var alertId = Str(alert, "id") ?? $"alert-{i}";
                var title = Str(alert, "title") ?? alertId;
                var source = Str(alert, "serviceSource") ?? Str(alert, "detectionSource") ?? "Microsoft Defender XDR";
                var alertRef = new TimelineRef("alert", alertId, title);
                var alertEntities = new List<string>();
                if (alert.TryGetProperty("evidence", out var evList) && evList.ValueKind == JsonValueKind.Array)
                    foreach (var ev in evList.EnumerateArray()) alertEntities.AddRange(EvidenceLabels(ev, deviceNames));

                var first = Time(alert, "firstActivityDateTime");
                var last = Time(alert, "lastActivityDateTime");
                if (first is { } f)
                    Add(new Acc { Ts = f, Kind = "alert", Lane = "attack", Action = $"Activity began: {title}", Entities = [.. alertEntities], Source = source, Refs = [alertRef] });
                if (last is { } l && l != first)
                    Add(new Acc { Ts = l, Kind = "alert", Lane = "attack", Action = $"Activity last seen: {title}", Entities = [.. alertEntities], Source = source, Refs = [alertRef] });
                if (Time(alert, "createdDateTime") is { } created)
                    Add(new Acc
                    {
                        Ts = created, Kind = "alert", Lane = "detection",
                        Action = $"Alert raised: {title}{(Str(alert, "severity") is { } sev ? $" ({sev})" : "")}",
                        Entities = [.. alertEntities], Source = source, Refs = [alertRef],
                    });

                if (evList.ValueKind == JsonValueKind.Array)
                    foreach (var ev in evList.EnumerateArray())
                        foreach (var e in EvidenceEvents(ev, deviceNames))
                        {
                            e.Refs.Add(alertRef);
                            e.InEvidence = true;
                            Add(e);
                        }
            }
        }

        // ── Board messages: reported events, findings, IOCs and verdicts ──────────────────────────
        foreach (var m in messages.OrderBy(m => long.TryParse(m.Seq, out var s) ? s : 0))
        {
            if (m.Type is not ("finding" or "ioc" or "verdict")) continue;
            var msgRef = new TimelineRef("message", m.Id.ToString(), $"{m.Type} by @{m.Author.Handle}");
            var thread = m.ParentId ?? m.Id;
            if (m.Payload is { ValueKind: JsonValueKind.Object } p && p.TryGetProperty("events", out var evs) && evs.ValueKind == JsonValueKind.Array)
                foreach (var e in evs.EnumerateArray())
                {
                    if (Time(e, "ts") is not { } ts || Str(e, "entity") is not { } entity || Str(e, "action") is not { } action) continue;
                    var refs = new List<TimelineRef> { msgRef };
                    if (Str(e, "ref") is { Length: > 0 } r) refs.Add(new TimelineRef("ref", r));
                    Add(new Acc
                    {
                        Ts = ts, Kind = m.Type, Lane = "attack", Action = action, Entities = [entity],
                        // Always attributed to the reporter; the source they claim is shown separately, as untrusted.
                        Source = $"reported by @{m.Author.Handle}", ClaimedSource = Str(e, "source"), Refs = refs, ReportedBy = [m.Author.Handle],
                        Reported = true, InEvidence = InEvidence(entity, evidence), ThreadId = thread,
                    });
                }

            switch (m.Type)
            {
                case "finding":
                    Add(new Acc
                    {
                        Ts = m.CreatedAt, Kind = "finding", Lane = "response", Action = $"Finding by @{m.Author.Handle}: {Excerpt(m.Body)}",
                        Entities = StringList(m.Payload, "entities"), Source = "board", Refs = [msgRef], ReportedBy = [m.Author.Handle], ThreadId = thread,
                    });
                    break;
                case "ioc":
                    var indicators = m.Payload is { ValueKind: JsonValueKind.Object } ip && ip.TryGetProperty("indicators", out var list) && list.ValueKind == JsonValueKind.Array
                        ? list.EnumerateArray().Select(x => (Value: Str(x, "value"), Verdict: Str(x, "verdict") ?? "unknown")).Where(x => x.Value is not null).ToList()
                        : [];
                    if (indicators.Count == 0) break;
                    Add(new Acc
                    {
                        Ts = m.CreatedAt, Kind = "ioc", Lane = "response",
                        Action = $"@{m.Author.Handle} reported {indicators.Count} indicator(s): {string.Join(", ", indicators.Take(5).Select(x => $"{x.Value} ({x.Verdict})"))}{(indicators.Count > 5 ? ", ..." : "")}",
                        Entities = indicators.Select(x => x.Value!).ToList(), Source = "board", Refs = [msgRef], ReportedBy = [m.Author.Handle], ThreadId = thread,
                    });
                    break;
                case "verdict":
                    var cls = Str(m.Payload, "classification") ?? "unknown";
                    var conf = m.Payload is { ValueKind: JsonValueKind.Object } vp && vp.TryGetProperty("confidence", out var c) && c.ValueKind == JsonValueKind.Number ? c.GetDouble() : (double?)null;
                    Add(new Acc
                    {
                        Ts = m.CreatedAt, Kind = "verdict", Lane = "response",
                        Action = $"Verdict by @{m.Author.Handle}: {IncidentSummary.ClassificationText.GetValueOrDefault(cls, cls)}{(conf is { } cv ? $", {Math.Round(cv * 100)}% confidence" : "")}",
                        Entities = [], Source = "board", Refs = [msgRef], ReportedBy = [m.Author.Handle], ThreadId = thread,
                    });
                    break;
            }
        }

        // ── Brokered actions: requested, approved, denied, executed, reverted ─────────────────────
        var executed = new List<(TimelineActionInput Action, string[] Targets)>();
        foreach (var a in actions.OrderBy(a => a.CreatedAt))
        {
            var def = Catalog.All.GetValueOrDefault(a.Kind);
            var title = def?.Title ?? a.Kind;
            string[] targets = [];
            string describe = title;
            if (def is not null)
            {
                try
                {
                    var prms = def.Validate(a.Params);
                    targets = def.TargetsOf(prms).All.ToArray();
                    describe = def.Describe(prms);
                }
                catch (Exception ex) when (ex is Core.BoardException or InvalidOperationException or JsonException) { }
            }
            var aRef = new TimelineRef("action", a.Id.ToString(), title);
            var refs = a.RequestMessageId is { } rm ? new List<TimelineRef> { aRef, new("message", rm.ToString(), "request") } : [aRef];
            Acc Act(DateTimeOffset ts, string text) => new()
            {
                Ts = ts, Kind = "action", Lane = "response", Action = text, Entities = [.. targets], Source = "blueboard broker", Refs = [.. refs],
            };
            Add(Act(a.CreatedAt, $"@{a.RequestedBy} requested: {describe}"));
            if (a.Status == "rejected") Add(Act(a.CreatedAt, $"Rejected by policy: {title}"));
            foreach (var (approver, at) in a.Approvals) Add(Act(at, $"@{approver} approved: {title}"));
            if (a.Approvals.Count == 0 && a.DecidedAt is { } da && a.Status is "approved" or "running" or "succeeded" or "failed" && a.DecidedBy is { } db)
                Add(Act(da, $"@{db} approved: {title}"));
            if (a.Status == "denied" && a.DecidedAt is { } dd) Add(Act(dd, $"@{a.DecidedBy ?? "approver"} denied: {title}"));
            if (a.Status == "expired" && a.DecidedAt is { } de) Add(Act(de, $"Expired without a decision: {title}"));
            if (a.FinishedAt is { } fin && a.Status is "succeeded" or "failed")
            {
                Add(Act(fin, a.Status == "succeeded"
                    ? $"Executed{(a.DryRun ? " (dry run)" : "")}: {describe}"
                    : $"Failed: {describe}{(a.Error is { Length: > 0 } err ? $" ({Excerpt(err)})" : "")}"));
                if (a.Status == "succeeded")
                {
                    var undoneId = a.Kind == "disable_detection_rule" && a.Params.ValueKind == JsonValueKind.Object
                        && a.Params.TryGetProperty("rule_action_id", out var rid) && rid.ValueKind == JsonValueKind.String ? rid.GetString() : null;
                    if (Reverts.TryGetValue(a.Kind, out var undoes)
                        && executed.LastOrDefault(x => x.Action.Kind == undoes && (undoneId is not null
                            ? string.Equals(x.Action.Id.ToString(), undoneId, StringComparison.OrdinalIgnoreCase)
                            : x.Targets.Intersect(targets, StringComparer.OrdinalIgnoreCase).Any())) is { Action: not null } prior)
                    {
                        var undone = Catalog.All.GetValueOrDefault(undoes)?.Title ?? undoes;
                        var revert = Act(fin, $"Reverted{(a.DryRun ? " (dry run)" : "")}: {undone}");
                        revert.Refs.Add(new TimelineRef("action", prior.Action.Id.ToString(), undone));
                        Add(revert);
                    }
                    executed.Add((a, targets));
                }
            }
        }

        var all = events.Values.OrderBy(e => e.Ts).ThenBy(e => LaneOrder(e.Lane)).ThenBy(e => e.Order).ToList();
        var filtered = all.Where(e =>
            (kindFilter is null || e.Kind == kindFilter)
            && (string.IsNullOrWhiteSpace(entityFilter) || e.Entities.Any(x => x.Contains(entityFilter.Trim(), StringComparison.OrdinalIgnoreCase)))).ToList();
        var take = Math.Clamp(limit, 1, 1000);
        var rows = filtered.Take(take).Select(e => new TimelineEvent(
            Id(DedupeKey(e)), e.Ts, e.Kind, e.Lane, e.Action, [.. e.Entities], e.Source, [.. e.Refs], [.. e.ReportedBy], e.Reported, e.InEvidence, e.ThreadId,
            e.Reported ? e.ClaimedSource : null)).ToList();
        return new IncidentTimelineResult(incidentId, graphId, rows, filtered.Count, filtered.Count > take, Notice);
    }

    /// <summary>Timestamped evidence: process starts, email delivery, sign-in sessions, and first sight of persistence-type artefacts.</summary>
    private static IEnumerable<Acc> EvidenceEvents(JsonElement ev, IReadOnlyDictionary<string, string> deviceNames)
    {
        var type = (Str(ev, "@odata.type") ?? "").Replace("#microsoft.graph.security.", "");
        var labels = EvidenceLabels(ev, deviceNames).ToList();
        switch (type)
        {
            case "processEvidence":
                var image = Str(O(ev, "imageFile"), "fileName") ?? "process";
                var cmd = Str(ev, "processCommandLine");
                if (Time(ev, "processCreationDateTime") is { } started)
                    yield return Evidence(started, $"Process started: {image}{(cmd is { Length: > 0 } ? $": {Excerpt(cmd)}" : "")}", labels, "Defender process evidence");
                var parent = Str(O(ev, "parentProcessImageFile"), "fileName");
                if (parent is not null && Time(ev, "parentProcessCreationDateTime") is { } pstarted)
                    yield return Evidence(pstarted, $"Parent process started: {parent}", labels, "Defender process evidence");
                break;
            case "analyzedMessageEvidence":
                if (Time(ev, "receivedDateTime") is { } received)
                {
                    var sender = Str(O(ev, "p1Sender"), "emailAddress") ?? Str(O(ev, "p2Sender"), "emailAddress");
                    yield return Evidence(received,
                        $"Email delivered{(Str(ev, "subject") is { } subj ? $": \"{Excerpt(subj)}\"" : "")}{(sender is not null ? $" from {sender}" : "")}{(Str(ev, "recipientEmailAddress") is { } rcpt ? $" to {rcpt}" : "")}",
                        labels, "Defender for Office 365");
                }
                break;
            case "cloudLogonSessionEvidence":
                if (Time(ev, "startUtcDateTime") is { } logon)
                    yield return Evidence(logon, $"Sign-in session started{(Str(ev, "browser") is { } b ? $" ({b})" : "")}", labels, "Entra sign-in evidence");
                if (Time(ev, "previousLogonDateTime") is { } prev)
                    yield return Evidence(prev, "Previous sign-in", labels, "Entra sign-in evidence");
                break;
            case "mailboxConfigurationEvidence":
                if (Time(ev, "createdDateTime") is { } mcfg)
                    yield return Evidence(mcfg, $"Mailbox configuration changed: {Str(ev, "configurationType") ?? Str(ev, "displayName") ?? "rule"}", labels, "Defender for Office 365");
                break;
            case "oauthApplicationEvidence":
            case "servicePrincipalEvidence":
                if (Time(ev, "createdDateTime") is { } app)
                    yield return Evidence(app, $"Application observed: {Str(ev, "displayName") ?? Str(ev, "appDisplayName") ?? Str(ev, "appId")}", labels, "Defender for Cloud Apps");
                break;
            case "azureResourceEvidence":
                if (Time(ev, "createdDateTime") is { } res)
                    yield return Evidence(res, $"Azure resource involved: {Str(ev, "resourceName") ?? Str(ev, "resourceId")}", labels, "Defender for Cloud");
                break;
        }
    }

    private static Acc Evidence(DateTimeOffset ts, string action, List<string> labels, string source) =>
        new() { Ts = ts, Kind = "evidence", Lane = "attack", Action = action, Entities = [.. labels], Source = source };

    /// <summary>Identifiers an evidence record names, friendliest first (device name before MDE id).</summary>
    internal static IEnumerable<string> EvidenceLabels(JsonElement ev, IReadOnlyDictionary<string, string> deviceNames)
    {
        var type = (Str(ev, "@odata.type") ?? "").Replace("#microsoft.graph.security.", "");
        IEnumerable<string?> Device(string? id, string? name) =>
            [name ?? (id is not null && deviceNames.TryGetValue(id, out var n) ? n : null), id];
        IEnumerable<string?> User(JsonElement? ua) => [Str(ua, "userPrincipalName"), Str(ua, "azureAdUserId")];
        IEnumerable<string?> File(JsonElement? f) => [Str(f, "fileName"), Str(f, "sha256"), Str(f, "sha1")];
        IEnumerable<string?> list = type switch
        {
            "deviceEvidence" => Device(Str(ev, "mdeDeviceId"), Str(ev, "deviceDnsName") ?? Str(ev, "hostName")),
            "userEvidence" => User(O(ev, "userAccount")),
            "ipEvidence" => [Str(ev, "ipAddress")],
            "urlEvidence" => [Str(ev, "url")],
            "dnsEvidence" => [Str(ev, "domainName")],
            "fileEvidence" => File(O(ev, "fileDetails")),
            "processEvidence" => Device(Str(ev, "mdeDeviceId"), null).Concat(User(O(ev, "userAccount"))).Concat(File(O(ev, "imageFile"))),
            "analyzedMessageEvidence" => [Str(ev, "recipientEmailAddress"), Str(O(ev, "p1Sender"), "emailAddress"), Str(ev, "networkMessageId")],
            "mailboxEvidence" => [Str(ev, "primaryAddress")],
            "mailboxConfigurationEvidence" => [Str(ev, "mailboxPrimaryAddress")],
            "cloudLogonSessionEvidence" => User(O(O(ev, "account"), "userAccount")),
            "oauthApplicationEvidence" => [Str(ev, "displayName"), Str(ev, "appId")],
            "servicePrincipalEvidence" => [Str(ev, "appDisplayName") ?? Str(ev, "servicePrincipalName"), Str(ev, "appId")],
            "cloudApplicationEvidence" => [Str(ev, "displayName")],
            "azureResourceEvidence" => [Str(ev, "resourceName"), Str(ev, "resourceId")],
            "blobEvidence" or "blobContainerEvidence" => [Str(ev, "name"), Str(ev, "url")],
            _ => [],
        };
        return list.OfType<string>().Where(s => s.Length > 0);
    }

    private static bool InEvidence(string entity, HashSet<string> evidence)
    {
        var v = entity.Trim();
        if (evidence.Contains(v) || evidence.Contains(v.TrimEnd('/'))) return true;
        return IncidentSummary.Identifiers(v).Any(evidence.Contains);
    }

    private static int LaneOrder(string lane) => lane switch { "attack" => 0, "detection" => 1, _ => 2 };

    private static string DedupeKey(Acc e) =>
        $"{e.Ts.ToUniversalTime():yyyy-MM-ddTHH:mm:ss}|{e.Lane}|{e.Action.Trim().ToLowerInvariant()}|{string.Join(",", e.Entities.Select(x => x.ToLowerInvariant()).Order(StringComparer.Ordinal))}";

    private static string Id(string key) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..16];

    private static List<string> StringList(JsonElement? e, string k) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
            : [];

    internal static string Excerpt(string text)
    {
        var line = string.Join(" ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return line.Length <= 160 ? line : line[..157] + "...";
    }

    private static DateTimeOffset? Time(JsonElement? e, string k) =>
        Str(e, k) is { } s && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t) && t.Year > 1971 ? t : null;

    private static string? Str(JsonElement? e, string k) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static JsonElement? O(JsonElement? e, string k) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(k, out var v) ? v : null;
}
