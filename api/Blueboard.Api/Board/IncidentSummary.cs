using Blueboard.Contracts;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;

namespace Blueboard.Api.Board;

public sealed record SummaryVerdict(
    Guid MessageId, Guid ThreadId, string Classification, double Confidence, string? Determination,
    string Author, string AuthorName, string AuthorKind, DateTimeOffset At, string[] NotInEvidence);

public sealed record SummaryIoc(
    string Kind, string Value, string Verdict, DateTimeOffset FirstSeen, string[] Reporters, Guid[] MessageIds, Guid ThreadId,
    bool InEvidence, bool NotInEvidence);

public sealed record SummaryAction(Guid Id, string Kind, string Title, string Status, string StatusText, string RequestedBy, Guid? RequestMessageId, DateTimeOffset CreatedAt);
public sealed record SummaryAsk(Guid MessageId, Guid ThreadId, string Excerpt, string Author, DateTimeOffset CreatedAt, long AgeSeconds);
public sealed record SummaryEntity(string Kind, string Id, string Label);
public sealed record SummaryStep(string Id, string Title, string Stage, string State, Guid? MessageId, Guid? ThreadId, string? ClaimedBy, string? SuggestedAction);
public sealed record SummaryPlaybook(string Id, string Title, int Done, int Total, IReadOnlyList<SummaryStep> Steps);

public sealed record IncidentSummaryResult(
    SummaryVerdict? Verdict,
    bool VerdictsDisagree,
    IReadOnlyList<SummaryVerdict> Verdicts,
    IReadOnlyList<SummaryIoc> Iocs,
    IReadOnlyList<SummaryAction> Actions,
    IReadOnlyList<SummaryAsk> OpenAsks,
    IReadOnlyList<SummaryEntity> Entities,
    SummaryPlaybook? Playbook,
    string Markdown);

/// <summary>The incident header the summary needs, as stored from Defender.</summary>
public sealed record SummaryIncident(string GraphId, string DisplayName, string Severity, string Status, JsonElement Data);

/// <summary>An action linked to the incident (from the actions table, the source of truth for status).</summary>
public sealed record SummaryActionInput(Guid Id, string Kind, string Status, string RequestedBy, Guid? RequestMessageId, DateTimeOffset CreatedAt);

/// <summary>
/// Deterministic roll-up of an incident's stored messages: never written by a model, so it is repeatable and auditable.
/// Board content is untrusted, so the Markdown export escapes everything that came from a message or from Defender.
/// </summary>
public static partial class IncidentSummary
{
    private static readonly Dictionary<string, int> VerdictRank = new() { ["malicious"] = 3, ["suspicious"] = 2, ["benign"] = 1, ["unknown"] = 0 };

    public static readonly IReadOnlyDictionary<string, string> ClassificationText = new Dictionary<string, string>
    {
        ["truePositive"] = "true positive", ["falsePositive"] = "false positive",
        ["informationalExpectedActivity"] = "expected activity", ["unknown"] = "unknown",
    };

    public static readonly IReadOnlyDictionary<string, string> ActionStatusText = new Dictionary<string, string>
    {
        ["pending_approval"] = "waiting for approval", ["approved"] = "approved, about to run", ["running"] = "running",
        ["succeeded"] = "done", ["failed"] = "failed", ["denied"] = "denied", ["rejected"] = "rejected by policy",
    };

    // Identifiers a verdict or finding can cite: IPv4, URLs, e-mail addresses / UPNs, hashes and domain names.
    [GeneratedRegex(@"https?://[^\s<>()\[\]`'""]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b|\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")]
    private static partial Regex IdentifierRegex();

    // "update.exe" looks like a domain to the pattern above; file names are not network identifiers.
    private static readonly HashSet<string> FileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "sys", "bat", "cmd", "ps", "js", "vbs", "hta", "lnk", "msi", "iso", "zip", "rar", "txt", "log", "csv", "json",
        "xml", "html", "htm", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "png", "jpg", "gif", "tmp", "dat", "eml", "msg",
    };

    /// <summary>Identifier-like tokens in free text (lower-cased, trailing punctuation removed).</summary>
    public static IEnumerable<string> Identifiers(string text) =>
        IdentifierRegex().Matches(text)
            .Select(m => m.Value.TrimEnd('.', ',', ';', ':', '!', '?').ToLowerInvariant())
            .Where(v => v.Length > 3 && (v.Contains('/') || v.Contains('@') || !FileExtensions.Contains(v[(v.LastIndexOf('.') + 1)..])))
            .Distinct();

    public static IncidentSummaryResult Build(
        SummaryIncident incident, IReadOnlyList<Message> messages, IReadOnlyList<SummaryActionInput> actions,
        Playbook? playbook, DateTimeOffset now)
    {
        var entities = Graph.Entities.Extract(incident.Data);
        var evidence = EvidenceSet(incident.Data, entities);
        var findings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in messages.Where(m => m.Type == "finding"))
        {
            foreach (var id in Identifiers(f.Body)) findings.Add(id);
            if (f.Payload is { } p) foreach (var s in Leaves(p)) { findings.Add(s); foreach (var id in Identifiers(s)) findings.Add(id); }
        }
        bool InEvidence(string v) => evidence.Contains(v) || evidence.Contains(v.TrimEnd('/'));
        bool Grounded(string v) => InEvidence(v) || findings.Contains(v);

        // Messages arrive in seq order; keep that order so "latest" means the highest seq.
        var ordered = messages.OrderBy(m => long.Parse(m.Seq)).ToList();

        var verdicts = ordered.Where(m => m.Type == "verdict" && Str(m.Payload, "classification") is not null)
            .Select(m => new SummaryVerdict(m.Id, m.ParentId ?? m.Id, Str(m.Payload, "classification")!, Num(m.Payload, "confidence") ?? 0, Str(m.Payload, "determination"),
                m.Author.Handle, m.Author.DisplayName, m.Author.Kind, m.CreatedAt,
                Identifiers(m.Body).Where(v => !Grounded(v)).ToArray()))
            .ToList();
        var latestPerAuthor = verdicts.GroupBy(v => v.Author).Select(g => g.Last()).OrderBy(v => v.At).ToList();
        var disagree = latestPerAuthor.Select(v => v.Classification).Distinct().Count() > 1;

        var iocs = new Dictionary<(string, string), (string Kind, string Value, string Verdict, DateTimeOffset First, List<string> Reporters, List<Guid> Ids, Guid Thread)>();
        foreach (var m in ordered.Where(m => m.Type == "ioc"))
        {
            if (m.Payload is not { } p || !p.TryGetProperty("indicators", out var list) || list.ValueKind != JsonValueKind.Array) continue;
            foreach (var i in list.EnumerateArray())
            {
                if (Str(i, "kind") is not { } kind || Str(i, "value") is not { Length: > 0 } value) continue;
                var verdict = Str(i, "verdict") ?? "unknown";
                var key = (kind, value.Trim().ToLowerInvariant());
                if (!iocs.TryGetValue(key, out var e)) e = (kind, value.Trim(), verdict, m.CreatedAt, [], [], m.ParentId ?? m.Id);
                if (VerdictRank.GetValueOrDefault(verdict) > VerdictRank.GetValueOrDefault(e.Verdict)) e.Verdict = verdict;
                if (!e.Reporters.Contains(m.Author.Handle)) e.Reporters.Add(m.Author.Handle);
                if (!e.Ids.Contains(m.Id)) e.Ids.Add(m.Id);
                iocs[key] = e;
            }
        }
        var iocRows = iocs.Values
            .Select(e => new SummaryIoc(e.Kind, e.Value, e.Verdict, e.First, [.. e.Reporters], [.. e.Ids], e.Thread, InEvidence(e.Value.ToLowerInvariant()), !Grounded(e.Value.ToLowerInvariant())))
            .OrderByDescending(i => VerdictRank.GetValueOrDefault(i.Verdict)).ThenBy(i => i.FirstSeen).ToList();

        var actionRows = actions.OrderBy(a => a.CreatedAt)
            .Select(a => new SummaryAction(a.Id, a.Kind, Catalog.All.TryGetValue(a.Kind, out var d) ? d.Title : a.Kind, a.Status,
                ActionStatusText.GetValueOrDefault(a.Status, a.Status), a.RequestedBy, a.RequestMessageId, a.CreatedAt))
            .ToList();

        var asks = ordered.Where(m => m.Type == "question" && m.ClaimState == "open" && !PlaybookRunner.IsChecklist(m.Payload))
            .Select(m => new SummaryAsk(m.Id, m.ParentId ?? m.Id, Excerpt(m.Body), m.Author.Handle, m.CreatedAt, (long)Math.Max(0, (now - m.CreatedAt).TotalSeconds)))
            .ToList();

        var chips = new List<SummaryEntity>();
        foreach (var u in entities.Users)
            if ((u.Upn ?? u.AadUserId) is { } id) chips.Add(new SummaryEntity("user", id, u.Upn ?? u.Name ?? id));
        foreach (var d in entities.Devices)
            if ((d.MdeDeviceId ?? d.Name) is { } id) chips.Add(new SummaryEntity("device", id, d.Name ?? id));

        var pb = PlaybookProgress(playbook, ordered);
        var latest = verdicts.LastOrDefault();
        var result = new IncidentSummaryResult(latest, disagree, latestPerAuthor, iocRows, actionRows, asks, chips, pb, "");
        return result with { Markdown = ToMarkdown(incident, result, now) };
    }

    private static SummaryPlaybook? PlaybookProgress(Playbook? playbook, List<Message> ordered)
    {
        var posted = ordered.Where(m => m.Type == "question" && PlaybookRunner.IsChecklist(m.Payload))
            .Select(m => (Message: m, Checklist: m.Payload!.Value.GetProperty("checklist")))
            .ToList();
        if (playbook is null && posted.Count == 0) return null;
        var byStep = posted.GroupBy(p => Str(p.Checklist, "step") ?? "").ToDictionary(g => g.Key, g => g.First().Message);
        IEnumerable<SummaryStep> steps = playbook is not null
            ? playbook.Steps.Select(s => byStep.TryGetValue(s.Id, out var m)
                ? new SummaryStep(s.Id, s.Title, s.Stage, m.ClaimState, m.Id, m.ParentId ?? m.Id, m.ClaimedBy, s.SuggestedAction)
                : new SummaryStep(s.Id, s.Title, s.Stage, "hidden", null, null, null, s.SuggestedAction))
            : posted.Select(p => new SummaryStep(Str(p.Checklist, "step") ?? "", Excerpt(p.Message.Body), Str(p.Checklist, "stage") ?? "",
                p.Message.ClaimState, p.Message.Id, p.Message.ParentId ?? p.Message.Id, p.Message.ClaimedBy, Str(p.Checklist, "suggested_action")));
        var list = steps.ToList();
        var id = playbook?.Id ?? Str(posted[0].Checklist, "playbook") ?? "";
        var title = playbook?.Title ?? Str(posted[0].Checklist, "playbook_title") ?? id;
        var total = playbook?.Steps.Count ?? (int)(Num(posted[0].Checklist, "total") ?? list.Count);
        return new SummaryPlaybook(id, title, list.Count(s => s.State == "done"), total, list);
    }

    /// <summary>Every string in the stored Defender payload, plus the identifiers inside them and the extracted entity keys.</summary>
    internal static HashSet<string> EvidenceSet(JsonElement data, IncidentEntities entities)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in Leaves(data))
        {
            if (s.Length is 0 or > 4096) continue;
            set.Add(s.Trim().TrimEnd('/'));
            foreach (var id in Identifiers(s)) set.Add(id);
        }
        foreach (var k in entities.Keys()) set.Add(k);
        foreach (var d in entities.Domains) set.Add(d);
        return set;
    }

    private static IEnumerable<string> Leaves(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.String: yield return e.GetString()!; break;
            case JsonValueKind.Array: foreach (var x in e.EnumerateArray()) foreach (var s in Leaves(x)) yield return s; break;
            case JsonValueKind.Object: foreach (var p in e.EnumerateObject()) foreach (var s in Leaves(p.Value)) yield return s; break;
        }
    }

    private static string Excerpt(string body)
    {
        var line = string.Join(" ", body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return line.Length <= 160 ? line : line[..157] + "...";
    }

    // ── Markdown export ────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Escapes untrusted text for Markdown: no raw HTML (angle brackets become entities), no links, emphasis or tables
    /// injected from a message body, and one line only.
    /// </summary>
    public static string Md(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var sb = new StringBuilder(text.Length + 8);
        foreach (var c in text)
        {
            switch (c)
            {
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '&': sb.Append("&amp;"); break;
                case '\r': break;
                case '\n': sb.Append(' '); break;
                case '\\' or '`' or '*' or '_' or '[' or ']' or '(' or ')' or '#' or '|' or '!' or '~': sb.Append('\\').Append(c); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    private static string Age(long seconds) => seconds switch
    {
        < 3600 => $"{Math.Max(1, seconds / 60)} min",
        < 86400 => $"{seconds / 3600} h",
        _ => $"{seconds / 86400} d",
    };

    public static string ToMarkdown(SummaryIncident inc, IncidentSummaryResult s, DateTimeOffset now)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"## Incident {Md(inc.GraphId)}: {Md(inc.DisplayName)}");
        sb.AppendLine();
        sb.AppendLine($"Severity: {Md(inc.Severity)} · Defender status: {Md(inc.Status)} · Summary from blueboard at {now:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine();
        sb.AppendLine("### Verdict");
        if (s.Verdict is { } v)
        {
            sb.AppendLine($"- {Md(ClassificationText.GetValueOrDefault(v.Classification, v.Classification))}, {Math.Round(v.Confidence * 100)}% confidence, by @{Md(v.Author)} at {v.At:yyyy-MM-dd HH:mm} UTC"
                          + (v.Determination is { } d ? $" ({Md(d)})" : ""));
            if (v.NotInEvidence.Length > 0) sb.AppendLine($"- Not in evidence: {string.Join(", ", v.NotInEvidence.Select(Md))}");
            if (s.VerdictsDisagree)
                sb.AppendLine($"- Verdicts disagree: {string.Join("; ", s.Verdicts.Select(x => $"@{Md(x.Author)} {Md(ClassificationText.GetValueOrDefault(x.Classification, x.Classification))}"))}");
        }
        else sb.AppendLine("- No verdict yet.");
        sb.AppendLine();

        sb.AppendLine("### Indicators");
        if (s.Iocs.Count == 0) sb.AppendLine("- None reported.");
        foreach (var i in s.Iocs)
            sb.AppendLine($"- {Md(i.Kind)} {Md(i.Value)}: {Md(i.Verdict)}, reported by {string.Join(", ", i.Reporters.Select(r => "@" + Md(r)))}"
                          + (i.InEvidence ? ", in incident evidence" : i.NotInEvidence ? ", not in evidence" : ", in a finding"));
        sb.AppendLine();

        sb.AppendLine("### Actions");
        if (s.Actions.Count == 0) sb.AppendLine("- None requested.");
        foreach (var a in s.Actions) sb.AppendLine($"- {Md(a.Title)}: {Md(a.StatusText)} (requested by @{Md(a.RequestedBy)})");
        sb.AppendLine();

        sb.AppendLine("### Open asks");
        if (s.OpenAsks.Count == 0) sb.AppendLine("- None.");
        foreach (var q in s.OpenAsks) sb.AppendLine($"- {Md(q.Excerpt)} (@{Md(q.Author)}, open {Age(q.AgeSeconds)})");

        if (s.Playbook is { } pb)
        {
            sb.AppendLine();
            sb.AppendLine($"### Playbook: {Md(pb.Title)} ({pb.Done} of {pb.Total} steps done)");
            foreach (var st in pb.Steps) sb.AppendLine($"- [{(st.State == "done" ? "x" : " ")}] {Md(st.Title)} ({Md(st.Stage)}, {StepStateText(st)})");
        }

        if (s.Entities.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("### Entities");
            foreach (var e in s.Entities) sb.AppendLine($"- {Md(e.Kind)}: {Md(e.Label)}");
        }
        return sb.ToString().TrimEnd() + "\n";
    }

    private static string StepStateText(SummaryStep s) => s.State switch
    {
        "done" => $"done by @{Md(s.ClaimedBy)}",
        "claimed" => $"claimed by @{Md(s.ClaimedBy)}",
        "open" => "open",
        _ => "waiting on earlier steps",
    };

    private static string? Str(JsonElement? e, string k) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static double? Num(JsonElement? e, string k) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : null;
}
