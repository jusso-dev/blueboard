using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Contracts;

namespace Blueboard.Api.Ops;

/// <summary>A person who can be notified, with their effective settings (board defaults with their own overrides laid over).</summary>
public sealed record Person(string Handle, string DisplayName, string? Email, string[] Roles, NotificationSettings Settings)
{
    public NotificationRecipient Recipient => new(Handle, DisplayName, Email);
    public bool IsApprover => Roles.Contains(Core.Roles.Approver);
}

/// <summary>What the rules need to know about one board message. Built from the database; no message text.</summary>
public sealed record MessageFacts(
    Guid Id, string Type, string AuthorHandle, string AuthorKind, string[] Mentions, Guid? ParentId,
    string? IncidentSeverity, string? Classification,
    // Humans who started or posted in this message's thread before it (empty for a thread root).
    string[] ThreadHumans,
    // For a board action_result: the human who requested the action and the author of the instruction it acted on.
    string[] ActionHumans);

/// <summary>One event for one message: a per-person notice (Recipient set) or a board-wide one (Recipient null).</summary>
public sealed record EventFor(string Event, string? Recipient, IReadOnlyList<Person> To);

/// <summary>One notice to send (or hold) on one sink.</summary>
public sealed record Planned(string Event, string? Recipient, string Sink, IReadOnlyList<Person> To, DateTimeOffset? HoldUntil, bool IncludeSummary);

/// <summary>
/// Pure notification rules: the settings document (defaults, strict validation, merge patches), quiet hours, which
/// messages produce which events for whom, and routing to sinks. No I/O, so every rule is unit-tested directly.
/// </summary>
public static partial class NotificationRules
{
    public static readonly string[] EventKeys = ["approvals", "mention", "question", "reply", "verdict", "finding", "incident", "action_result"];
    public static readonly string[] SinkKeys = ["webhook", "teams", "mail", "ntfy"];
    /// <summary>Payloads.Verdict's classifications (the Defender incident classification values).</summary>
    public static readonly string[] Classifications = ["truePositive", "falsePositive", "informationalExpectedActivity", "unknown"];
    public static readonly string[] Severities = ["informational", "low", "medium", "high"];

    /// <summary>Built-in defaults. "Found something" = a true positive or undetermined verdict; the benign ones stay quiet.</summary>
    public static NotificationSettings BuiltIn { get; } = new(
        Enabled: true,
        Events: new(Approvals: true, Mention: true, Question: true, Reply: true, Verdict: true, Finding: false, Incident: false, ActionResult: true),
        VerdictClassifications: ["truePositive", "unknown"],
        MinIncidentSeverity: "high",
        MentionsFromPeople: false,
        IncludeSummary: true,
        QuietHours: new(Enabled: false, Start: "22:00", End: "07:00", TimeZone: "Australia/Sydney", ExceptHighSeverity: true),
        Sinks: new(Webhook: true, Teams: true, Mail: true, Ntfy: true));

    // ── settings documents ───────────────────────────────────────────────────────────────────────
    private enum Kind { Bool, Severity, Time, Zone, Classifications, Object }
    private sealed record Field(Kind Kind, IReadOnlyDictionary<string, Field>? Children = null);

    private static readonly Field Bool = new(Kind.Bool);
    private static Field Obj(params (string, Field)[] f) => new(Kind.Object, f.ToDictionary(x => x.Item1, x => x.Item2));

    private static readonly Field Schema = Obj(
        ("enabled", Bool),
        ("events", Obj(EventKeys.Select(k => (k, Bool)).ToArray())),
        ("verdict_classifications", new(Kind.Classifications)),
        ("min_incident_severity", new(Kind.Severity)),
        ("mentions_from_people", Bool),
        ("include_summary", Bool),
        ("quiet_hours", Obj(("enabled", Bool), ("start", new(Kind.Time)), ("end", new(Kind.Time)), ("time_zone", new(Kind.Zone)), ("except_high_severity", Bool))),
        ("sinks", Obj(SinkKeys.Select(k => (k, Bool)).ToArray())));

    [GeneratedRegex(@"^([01][0-9]|2[0-3]):[0-5][0-9]$")] private static partial Regex HhMm();
    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+)*$")] private static partial Regex IanaLike();

    /// <summary>
    /// Validates a merge patch (or a stored partial document) strictly: an object, known keys only, the right type
    /// for each, HH:mm times, an IANA time zone this host knows, known severities and classifications. null resets a
    /// field when <paramref name="allowNull"/>. Throws BoardException (400) naming the field.
    /// </summary>
    public static JsonObject ValidatePatch(JsonElement patch, bool allowNull = true)
    {
        if (patch.ValueKind != JsonValueKind.Object) throw new BoardException("notification settings must be a JSON object");
        var node = JsonNode.Parse(patch.GetRawText())!.AsObject();
        Check(node, Schema, "", allowNull);
        return node;
    }

    private static void Check(JsonObject o, Field schema, string at, bool allowNull)
    {
        foreach (var (key, value) in o)
        {
            var path = at.Length == 0 ? key : $"{at}.{key}";
            if (!schema.Children!.TryGetValue(key, out var f)) throw new BoardException($"unknown notification setting {path}");
            if (value is null)
            {
                if (!allowNull) throw new BoardException($"{path} must not be null");
                continue;
            }
            switch (f.Kind)
            {
                case Kind.Object:
                    if (value is not JsonObject child) throw new BoardException($"{path} must be an object");
                    Check(child, f, path, allowNull);
                    break;
                case Kind.Bool:
                    if (value.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False)) throw new BoardException($"{path} must be true or false");
                    break;
                case Kind.Severity:
                    if (Str(value) is not { } s || !Severities.Contains(s)) throw new BoardException($"{path} must be one of {string.Join(", ", Severities)}");
                    break;
                case Kind.Time:
                    if (Str(value) is not { } t || !HhMm().IsMatch(t)) throw new BoardException($"{path} must be a time as HH:mm (00:00–23:59)");
                    break;
                case Kind.Zone:
                    if (Str(value) is not { } z || ZoneOrNull(z) is null) throw new BoardException($"{path} must be an IANA time zone such as Australia/Sydney");
                    break;
                case Kind.Classifications:
                    if (value is not JsonArray arr || arr.Count > Classifications.Length) throw new BoardException($"{path} must be a list of classifications");
                    var seen = new HashSet<string>();
                    foreach (var item in arr)
                        if (item is null || Str(item) is not { } c || !Classifications.Contains(c) || !seen.Add(c))
                            throw new BoardException($"{path} must list distinct values from {string.Join(", ", Classifications)}");
                    break;
            }
        }
    }

    private static string? Str(JsonNode n) => n.GetValueKind() == JsonValueKind.String ? n.GetValue<string>() : null;

    /// <summary>An IANA zone id this host knows (Windows ids such as "AUS Eastern Standard Time" are refused).</summary>
    public static TimeZoneInfo? ZoneOrNull(string id)
    {
        if (id.Length is 0 or > 64 || !IanaLike().IsMatch(id)) return null;
        try { return TimeZoneInfo.FindSystemTimeZoneById(id); }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException) { return null; }
    }

    /// <summary>Applies a validated merge patch to a stored partial document: null removes a field, objects merge, the rest replace. Empty objects are pruned.</summary>
    public static JsonObject ApplyPatch(JsonObject? stored, JsonObject patch)
    {
        var result = (JsonObject?)stored?.DeepClone() ?? new JsonObject();
        foreach (var (key, value) in patch)
        {
            if (value is null) result.Remove(key);
            else if (value is JsonObject po)
            {
                var merged = ApplyPatch(result[key] as JsonObject, po);
                if (merged.Count == 0) result.Remove(key); else result[key] = merged;
            }
            else result[key] = value.DeepClone();
        }
        return result;
    }

    /// <summary>A full document: <paramref name="baseDoc"/> with a partial document laid over it field by field (arrays replace).</summary>
    public static NotificationSettings Overlay(NotificationSettings baseDoc, JsonObject? partial)
    {
        if (partial is null || partial.Count == 0) return baseDoc;
        var full = JsonSerializer.SerializeToNode(baseDoc, Json.Options)!.AsObject();
        Lay(full, partial);
        return full.Deserialize<NotificationSettings>(Json.Options)!;
    }

    private static void Lay(JsonObject target, JsonObject over)
    {
        foreach (var (key, value) in over)
        {
            if (value is null) continue;
            if (value is JsonObject vo && target[key] is JsonObject to) Lay(to, vo);
            else target[key] = value.DeepClone();
        }
    }

    /// <summary>
    /// A person's effective settings: the board defaults with their overrides laid over. include_summary in the board
    /// defaults is a ceiling: when an admin turns it off, nobody's notices carry message text.
    /// </summary>
    public static NotificationSettings Effective(NotificationSettings defaults, JsonObject? mine)
    {
        var s = Overlay(defaults, mine);
        return defaults.IncludeSummary ? s : s with { IncludeSummary = false };
    }

    /// <summary>Dotted paths a patch touches (for the audit row: which settings changed, not their values).</summary>
    public static IReadOnlyList<string> Paths(JsonObject patch, string at = "")
    {
        var list = new List<string>();
        foreach (var (key, value) in patch)
        {
            var path = at.Length == 0 ? key : $"{at}.{key}";
            if (value is JsonObject o && o.Count > 0) list.AddRange(Paths(o, path)); else list.Add(path);
        }
        return list;
    }

    public static bool EventOn(NotificationSettings s, string evt) => evt switch
    {
        "approvals" => s.Events.Approvals,
        "mention" => s.Events.Mention,
        "question" => s.Events.Question,
        "reply" => s.Events.Reply,
        "verdict" => s.Events.Verdict,
        "finding" => s.Events.Finding,
        "incident" => s.Events.Incident,
        "action_result" => s.Events.ActionResult,
        _ => false,
    };

    public static bool SinkOn(NotificationSettings s, string sink) => sink switch
    {
        "webhook" => s.Sinks.Webhook,
        "teams" => s.Sinks.Teams,
        "mail" => s.Sinks.Mail,
        "ntfy" => s.Sinks.Ntfy,
        _ => false,
    };

    // ── quiet hours ──────────────────────────────────────────────────────────────────────────────
    /// <summary>
    /// When quiet hours are on and <paramref name="now"/> is inside the window, the instant the window ends (UTC);
    /// otherwise null. start &gt; end is an overnight window (22:00–07:00); start == end is an empty window.
    /// </summary>
    public static DateTimeOffset? QuietUntil(QuietHours q, DateTimeOffset now)
    {
        if (!q.Enabled || q.Start == q.End || ZoneOrNull(q.TimeZone) is not { } tz) return null;
        var start = TimeSpan.ParseExact(q.Start, @"hh\:mm", null);
        var end = TimeSpan.ParseExact(q.End, @"hh\:mm", null);
        var local = TimeZoneInfo.ConvertTime(now, tz);
        var t = local.TimeOfDay;
        var quiet = start < end ? t >= start && t < end : t >= start || t < end;
        if (!quiet) return null;
        var candidate = local.Date + end;
        if (candidate <= local.DateTime) candidate = candidate.AddDays(1);
        // A wall time skipped by a daylight-saving jump doesn't exist: end at the first minute that does.
        while (tz.IsInvalidTime(candidate)) candidate = candidate.AddMinutes(30);
        return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(candidate, DateTimeKind.Unspecified), tz), TimeSpan.Zero);
    }

    public static int SeverityRank(string? severity) => severity?.ToLowerInvariant() switch
    {
        "informational" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => -1,
    };

    public static bool IsHighSeverity(string? severity) => SeverityRank(severity) >= 3;

    // ── which events, for whom ───────────────────────────────────────────────────────────────────
    /// <summary>
    /// The events one message produces. Each person gets at most one event per message: their own (action_result,
    /// mention, question addressed to them) first, then board-wide ones (question with no human mentioned, verdict,
    /// finding, incident) for everyone subscribed, then reply for thread participants not otherwise told. The author
    /// is never notified about their own message, and only agents' messages count as "found / needs something":
    /// the board's own posts produce only incident and action_result.
    /// </summary>
    public static IReadOnlyList<EventFor> Events(MessageFacts m, IReadOnlyList<Person> people)
    {
        var byHandle = people.Where(p => p.Settings.Enabled && p.Handle != m.AuthorHandle).ToDictionary(p => p.Handle);
        var assigned = new Dictionary<string, string>();
        var agent = m.AuthorKind == "agent";
        var system = m.AuthorKind == "system";
        var mentionedHumans = m.Mentions.Where(byHandle.ContainsKey).Distinct().ToList();
        // "Mentioned" counts every human principal, even one who turned notifications off: a question addressed to
        // someone is not broadcast to the board.
        var anyHumanMentioned = m.Mentions.Any(h => h != m.AuthorHandle && people.Any(p => p.Handle == h));

        if (system && m.Type == "action_result")
            foreach (var h in m.ActionHumans.Distinct())
                if (byHandle.TryGetValue(h, out var p) && p.Settings.Events.ActionResult) assigned[h] = "action_result";

        if (agent)
            foreach (var h in mentionedHumans)
            {
                var s = byHandle[h].Settings;
                var evt = m.Type == "question" && s.Events.Question ? "question" : s.Events.Mention ? "mention" : null;
                if (evt is not null) assigned.TryAdd(h, evt);
            }
        else if (m.AuthorKind == "human")
            foreach (var h in mentionedHumans)
                if (byHandle[h].Settings is { MentionsFromPeople: true, Events.Mention: true }) assigned.TryAdd(h, "mention");

        var list = assigned.GroupBy(kv => (kv.Value, kv.Key)).Select(g => new EventFor(g.Key.Value, g.Key.Key, [byHandle[g.Key.Key]])).ToList();

        string? boardWide = null;
        Func<NotificationSettings, bool> wants = _ => false;
        if (agent && m.Type == "question" && !anyHumanMentioned) (boardWide, wants) = ("question", s => s.Events.Question);
        else if (agent && m.Type == "verdict" && m.Classification is { } c) (boardWide, wants) = ("verdict", s => s.Events.Verdict && s.VerdictClassifications.Contains(c));
        else if (agent && m.Type == "finding" && m.IncidentSeverity is { } fs)
            (boardWide, wants) = ("finding", s => s.Events.Finding && SeverityRank(fs) >= SeverityRank(s.MinIncidentSeverity));
        else if (system && m.Type == "incident" && m.ParentId is null)
            (boardWide, wants) = ("incident", s => s.Events.Incident && SeverityRank(m.IncidentSeverity) >= SeverityRank(s.MinIncidentSeverity));
        var told = new HashSet<string>(assigned.Keys);
        if (boardWide is not null)
        {
            var to = byHandle.Values.Where(p => !told.Contains(p.Handle) && wants(p.Settings)).OrderBy(p => p.Handle, StringComparer.Ordinal).ToList();
            if (to.Count > 0) list.Add(new EventFor(boardWide, null, to));
            told.UnionWith(to.Select(p => p.Handle));
        }

        if (agent && m.ParentId is not null)
            foreach (var h in m.ThreadHumans.Distinct().Order(StringComparer.Ordinal))
                if (!told.Contains(h) && byHandle.TryGetValue(h, out var p) && p.Settings.Events.Reply)
                    list.Add(new EventFor("reply", h, [p]));
        return list;
    }

    /// <summary>
    /// Routes events to the ready sinks each recipient has on. A recipient in quiet hours gets their own held notice
    /// (sent when the window ends) unless the incident is high severity and they chose except_high_severity. The
    /// summary is included only when the board default allows it and every recipient of that notice wants it.
    /// </summary>
    public static IReadOnlyList<Planned> Route(IReadOnlyList<EventFor> events, IReadOnlyList<string> sinks, NotificationSettings defaults, string? incidentSeverity, DateTimeOffset now)
    {
        var high = IsHighSeverity(incidentSeverity);
        DateTimeOffset? Hold(Person p) => p.Settings.QuietHours.ExceptHighSeverity && high ? null : QuietUntil(p.Settings.QuietHours, now);
        bool Summary(IEnumerable<Person> to) => defaults.IncludeSummary && to.All(p => p.Settings.IncludeSummary);
        var plan = new List<Planned>();
        foreach (var e in events)
            foreach (var sink in sinks)
            {
                var on = e.To.Where(p => SinkOn(p.Settings, sink)).ToList();
                if (on.Count == 0) continue;
                var awake = on.Where(p => Hold(p) is null).ToList();
                if (e.Recipient is not null)
                {
                    plan.Add(new(e.Event, e.Recipient, sink, on, Hold(on[0]), Summary(on)));
                    continue;
                }
                if (awake.Count > 0) plan.Add(new(e.Event, null, sink, awake, null, Summary(awake)));
                foreach (var p in on.Except(awake)) plan.Add(new(e.Event, p.Handle, sink, [p], Hold(p), Summary([p])));
            }
        return plan;
    }

    /// <summary>
    /// Approver notices on one sink. Approvers who want them and are awake get it now. When every approver who wants
    /// it is in quiet hours it is held until the first window ends (unless the incident is high severity and they
    /// chose except_high_severity). With no approver signed in yet, the board default decides, as before these
    /// settings existed. Nobody wanting it: skipped.
    /// </summary>
    public static (bool Send, IReadOnlyList<Person> To, DateTimeOffset? HoldUntil) Approvals(IReadOnlyList<Person> people, NotificationSettings defaults, string sink, string? incidentSeverity, DateTimeOffset now)
    {
        var high = IsHighSeverity(incidentSeverity);
        static bool Wants(NotificationSettings s, string sink) => s.Enabled && s.Events.Approvals && SinkOn(s, sink);
        DateTimeOffset? Quiet(NotificationSettings s) => s.QuietHours.ExceptHighSeverity && high ? null : QuietUntil(s.QuietHours, now);
        var approvers = people.Where(p => p.IsApprover).ToList();
        if (approvers.Count == 0) return (Wants(defaults, sink), [], null);
        var wanting = approvers.Where(p => Wants(p.Settings, sink)).OrderBy(p => p.Handle, StringComparer.Ordinal).ToList();
        var awake = wanting.Where(p => Quiet(p.Settings) is null).ToList();
        if (awake.Count > 0) return (true, awake, null);
        if (wanting.Count > 0) return (true, wanting, wanting.Min(p => Quiet(p.Settings)));
        return (false, [], null);
    }

    // ── summary text ─────────────────────────────────────────────────────────────────────────────
    [GeneratedRegex(@"```.*?(```|$)", RegexOptions.Singleline)] private static partial Regex Fence();
    [GeneratedRegex(@"!?\[([^\]]*)\]\([^)]*\)")] private static partial Regex Link();
    [GeneratedRegex(@"<[^>]*>")] private static partial Regex Tag();
    [GeneratedRegex(@"(?m)^\s{0,3}(#{1,6}\s+|>\s?|[-*+]\s+|\d+[.)]\s+)")] private static partial Regex LineMarker();
    // Emphasis markers; an underscore only at a word edge, so snake_case and file_names survive.
    [GeneratedRegex(@"\*+|`+|~~|(?<!\w)_+|_+(?!\w)")] private static partial Regex Emphasis();
    [GeneratedRegex(@"\s+")] private static partial Regex Space();

    /// <summary>
    /// One plain line from untrusted Markdown, at most <paramref name="max"/> characters: code blocks become "[code]",
    /// links keep their text and lose their target, tags and emphasis go, line breaks become spaces. Sinks escape it again.
    /// </summary>
    public static string Summary(string? body, int max = 280)
    {
        if (string.IsNullOrWhiteSpace(body)) return "";
        var s = Fence().Replace(body, " [code] ");
        s = Link().Replace(s, "$1");
        s = Tag().Replace(s, " ");
        s = LineMarker().Replace(s, "");
        s = Emphasis().Replace(s, "");
        s = Space().Replace(Notifier.OneLine(s, int.MaxValue), " ").Trim();
        if (s.Length <= max) return s;
        var cut = s[..(max - 1)];
        if (char.IsHighSurrogate(cut[^1])) cut = cut[..^1];
        return cut.TrimEnd() + "…";
    }

    public static string ClassificationLabel(string? c) => c switch
    {
        "truePositive" => "True positive",
        "falsePositive" => "False positive",
        "informationalExpectedActivity" => "Expected activity",
        "unknown" => "Undetermined",
        _ => "Unclassified",
    };
}
