using Blueboard.Contracts;
using System.Text.Json;
using System.Text.RegularExpressions;
using Blueboard.Api.Actions;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Blueboard.Api.Board;

public sealed record PlaybookStep(string Id, string Stage, string Title, string? Detail, string[] After, string? SuggestedAction);
public sealed record PlaybookMatch(string[] Categories, string[] Titles, string[] Techniques, string[]? ServiceSources = null, string[]? Severities = null);
public sealed record Playbook(string Id, string Title, string File, PlaybookMatch Match, IReadOnlyList<PlaybookStep> Steps, string Notes, int Priority = 0);
public sealed record PlaybookProblem(string File, string Error);

/// <summary>The playbooks loaded at startup, plus the files that were skipped and why.</summary>
public sealed record PlaybookSet(IReadOnlyList<Playbook> All, IReadOnlyList<PlaybookProblem> Problems)
{
    public static readonly PlaybookSet Empty = new([], []);

    public Playbook? Get(string id) => All.FirstOrDefault(p => p.Id == id);

    /// <summary>The highest-priority (ties broken by file name order) playbook that matches the incident, or null.</summary>
    public Playbook? Match(JsonElement incident) =>
        All.OrderByDescending(p => p.Priority).FirstOrDefault(p => Playbooks.Matches(p.Match, incident));
}

/// <summary>
/// Playbooks are Markdown files (playbooks/*.md) with YAML front matter: what they match, and a checklist of steps.
/// They are operator-written config, validated at startup; a bad file is skipped and listed in <see cref="Problems"/>.
/// Playbooks never run actions: suggested_action only names a catalogue action a person or agent may request.
/// </summary>
public static partial class Playbooks
{
    public static readonly string[] Stages = ["triage", "investigate", "contain", "eradicate", "recover", "record"];
    private const int MaxSteps = 20;

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,40}$")] private static partial Regex Slug();
    [GeneratedRegex(@"^T\d{4}(\.\d{3})?$")] private static partial Regex Technique();

    /// <summary>The set loaded by the Function App at startup. A setup page can list <see cref="Problems"/>.</summary>
    public static PlaybookSet Current { get; set; } = PlaybookSet.Empty;
    public static IReadOnlyList<PlaybookProblem> Problems => Current.Problems;

    private static readonly IDeserializer Yaml = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .Build();

    public static PlaybookSet Load(string dir)
    {
        if (!Directory.Exists(dir)) return PlaybookSet.Empty;
        var all = new List<Playbook>();
        var problems = new List<PlaybookProblem>();
        foreach (var path in Directory.GetFiles(dir, "*.md").Order(StringComparer.Ordinal))
        {
            var file = Path.GetFileName(path);
            var (pb, error) = Parse(file, File.ReadAllText(path));
            if (pb is null) problems.Add(new PlaybookProblem(file, error ?? "invalid"));
            else if (all.Any(p => p.Id == pb.Id)) problems.Add(new PlaybookProblem(file, $"duplicate playbook id '{pb.Id}'"));
            else all.Add(pb);
        }
        return new PlaybookSet(all, problems);
    }

    public static (Playbook? Playbook, string? Error) Parse(string file, string text)
    {
        text = text.Replace("\r\n", "\n");
        if (!text.StartsWith("---\n", StringComparison.Ordinal)) return (null, "missing YAML front matter (the file must start with ---)");
        var end = text.IndexOf("\n---", 3, StringComparison.Ordinal);
        if (end < 0) return (null, "front matter is not closed with ---");
        FrontMatter fm;
        try
        {
            fm = Yaml.Deserialize<FrontMatter?>(text[4..(end + 1)]) ?? throw new YamlException("front matter is empty");
        }
        catch (YamlException ex)
        {
            return (null, $"invalid front matter: {(ex.InnerException ?? ex).Message}");
        }
        var notes = text[(end + 4)..].Trim();
        var error = Validate(fm, notes);
        if (error is not null) return (null, error);

        var steps = fm.Steps!.Select(s => new PlaybookStep(s.Id!, s.Stage!, s.Title!.Trim(), s.Detail?.Trim(), [.. s.After ?? []], s.SuggestedAction)).ToList();
        var match = new PlaybookMatch(
            [.. fm.Match!.Categories ?? []],
            [.. fm.Match.Titles ?? []],
            [.. fm.Match.Techniques ?? []],
            [.. fm.Match.ServiceSources ?? []],
            [.. fm.Match.Severities ?? []]);
        return (new Playbook(fm.Id!, fm.Title!.Trim(), file, match, steps, notes, fm.Priority ?? 0), null);
    }

    private static string? Validate(FrontMatter fm, string notes)
    {
        if (fm.Id is null || !Slug().IsMatch(fm.Id)) return "id must be a lower-case slug (a-z, 0-9, -)";
        if (fm.Title is not { Length: > 0 and <= 120 }) return "title is required (up to 120 characters)";
        if (fm.Priority is < -100 or > 1000) return "priority must be between -100 and 1000";
        if (notes.Length > 4000) return "notes after the front matter must be under 4000 characters";
        var m = fm.Match;
        if (m is null || (m.Categories ?? []).Count + (m.Titles ?? []).Count + (m.Techniques ?? []).Count + (m.ServiceSources ?? []).Count == 0)
            return "match needs at least one of categories, titles, techniques or service_sources";
        if ((m.Categories ?? []).Concat(m.Titles ?? []).Concat(m.ServiceSources ?? []).Concat(m.Severities ?? []).Any(s => s is not { Length: > 0 and <= 200 }))
            return "match entries must be 1-200 characters";
        if ((m.Techniques ?? []).FirstOrDefault(t => !Technique().IsMatch(t ?? "")) is { } bad) return $"invalid MITRE technique '{bad}' (use T1234 or T1234.001)";

        if (fm.Steps is not { Count: > 0 and <= MaxSteps }) return $"steps must list 1-{MaxSteps} steps";
        var ids = new HashSet<string>();
        foreach (var s in fm.Steps)
        {
            if (s.Id is null || !Slug().IsMatch(s.Id)) return "every step needs an id (a lower-case slug)";
            if (!ids.Add(s.Id)) return $"duplicate step id '{s.Id}'";
            if (s.Stage is null || !Stages.Contains(s.Stage)) return $"step '{s.Id}': stage must be one of {string.Join(", ", Stages)}";
            if (s.Title is not { Length: > 0 and <= 200 }) return $"step '{s.Id}': title is required (up to 200 characters)";
            if (s.Detail is { Length: > 2000 }) return $"step '{s.Id}': detail must be under 2000 characters";
            if (s.SuggestedAction is { } a && !Catalog.All.ContainsKey(a)) return $"step '{s.Id}': unknown suggested_action '{a}'";
        }
        foreach (var s in fm.Steps)
            foreach (var a in s.After ?? [])
                if (a == s.Id || !ids.Contains(a)) return $"step '{s.Id}': after refers to unknown step '{a}'";
        return HasCycle(fm.Steps) ? "steps depend on each other in a cycle" : null;
    }

    private static bool HasCycle(List<StepDoc> steps)
    {
        var after = steps.ToDictionary(s => s.Id!, s => s.After ?? []);
        var state = new Dictionary<string, int>(); // 1 visiting, 2 done
        bool Visit(string id)
        {
            if (state.GetValueOrDefault(id) == 2) return false;
            if (state.GetValueOrDefault(id) == 1) return true;
            state[id] = 1;
            if (after[id].Any(Visit)) return true;
            state[id] = 2;
            return false;
        }
        return steps.Any(s => Visit(s.Id!));
    }

    /// <summary>
    /// An incident matches when any alert category equals a listed category, the incident or an alert title contains a
    /// listed title, or a MITRE technique equals a listed one (T1566 also matches its sub-techniques, T1566.001).
    /// All comparisons ignore case.
    /// </summary>
    public static bool Matches(PlaybookMatch match, JsonElement incident)
    {
        var titles = new List<string>();
        var categories = new List<string>();
        var techniques = new List<string>();
        var sources = new List<string>();
        var severities = new List<string>();
        if (Str(incident, "displayName") is { } name) titles.Add(name);
        if (Str(incident, "severity") is { } incSev) severities.Add(incSev);
        if (incident.TryGetProperty("alerts", out var alerts) && alerts.ValueKind == JsonValueKind.Array)
            foreach (var a in alerts.EnumerateArray())
            {
                if (Str(a, "title") is { } t) titles.Add(t);
                if (Str(a, "category") is { } c) categories.Add(c);
                if (Str(a, "serviceSource") is { } src) sources.Add(src);
                if (Str(a, "severity") is { } aSev) severities.Add(aSev);
                if (a.TryGetProperty("mitreTechniques", out var mt) && mt.ValueKind == JsonValueKind.Array)
                    techniques.AddRange(mt.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : null).OfType<string>());
            }
        if (match.Severities is { Length: > 0 } reqSev && !reqSev.Any(s => severities.Contains(s, StringComparer.OrdinalIgnoreCase)))
            return false;
        return match.Categories.Any(c => categories.Contains(c, StringComparer.OrdinalIgnoreCase))
               || match.Titles.Any(t => titles.Any(x => x.Contains(t, StringComparison.OrdinalIgnoreCase)))
               || match.Techniques.Any(t => techniques.Any(x =>
                   x.Equals(t, StringComparison.OrdinalIgnoreCase) || x.StartsWith(t + ".", StringComparison.OrdinalIgnoreCase)))
               || (match.ServiceSources is { Length: > 0 } reqSrc && reqSrc.Any(s => sources.Contains(s, StringComparer.OrdinalIgnoreCase)));
    }

    private static string? Str(JsonElement e, string k) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    // YAML shapes. Unknown keys are an error, so a typo (sugested_action) is reported rather than ignored.
    private sealed class FrontMatter
    {
        public string? Id { get; set; }
        public string? Title { get; set; }
        public int? Priority { get; set; }
        public MatchDoc? Match { get; set; }
        public List<StepDoc>? Steps { get; set; }
    }

    private sealed class MatchDoc
    {
        public List<string>? Categories { get; set; }
        public List<string>? Titles { get; set; }
        public List<string>? Techniques { get; set; }
        public List<string>? ServiceSources { get; set; }
        public List<string>? Severities { get; set; }
    }

    private sealed class StepDoc
    {
        public string? Id { get; set; }
        public string? Stage { get; set; }
        public string? Title { get; set; }
        public string? Detail { get; set; }
        public List<string>? After { get; set; }
        public string? SuggestedAction { get; set; }
    }
}
