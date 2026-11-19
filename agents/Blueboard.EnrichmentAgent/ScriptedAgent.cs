using System.Text.Json;
using System.Text.Json.Serialization;
using Blueboard.Agent;
using Blueboard.Contracts;

/// <summary>
/// AGENT_MODE=scripted: the local demo's agent. No model and no key: it replays canned findings, IOCs, a verdict and
/// one request_action per incident from a fixture file, through the same board tools a real agent uses (so lookups
/// reach the mock Microsoft API and land in the audit log, and the action waits for a human). Mentions get a
/// canned reply. Never use this against a real tenant: the script's conclusions are fixed.
/// </summary>
sealed class ScriptedAgent(ScriptedAgent.Script script, TimeSpan delay)
{
    public sealed record Lookup(string Kind, string Value);
    public sealed record Post(string Body, JsonElement? Payload);
    public sealed record ActionStep(string Kind, JsonElement Params, string Justification);
    public sealed record Entry(Lookup[] Lookups, string? Hunt, Post Finding, JsonElement[] Iocs, JsonElement Verdict, string? Question, ActionStep? Action);
    public sealed record Script(Dictionary<string, Entry> Incidents, [property: JsonPropertyName("mention_reply")] string MentionReply);

    public static async Task<Script> LoadAsync(string path, CancellationToken ct) =>
        JsonSerializer.Deserialize<Script>(await File.ReadAllTextAsync(path, ct), BoardJson.Options)
        ?? throw new InvalidOperationException($"empty agent script {path}");

    public (AgentHandler Incident, AgentHandler Question, AgentHandler Mention) Handlers() => (OnIncident, OnQuestion, OnMention);

    private async Task OnIncident(WorkItem w, CancellationToken ct)
    {
        var id = w.Message.IncidentGraphId;
        if (id is null || !script.Incidents.TryGetValue(id, out var e))
        {
            Console.WriteLine($"[agent] no script for incident {id}: skipping");
            return;
        }
        Console.WriteLine($"[agent] scripted enrichment of incident {id}");
        await w.Board.GetIncidentAsync(id, ct);
        foreach (var l in e.Lookups) await Try(() => w.Board.LookupEntityAsync(l.Kind, l.Value, ct));
        if (e.Hunt is { } kql) await Try(() => w.Board.RunHuntingQueryAsync(kql, "P7D", ct));
        await Pause(ct);
        await w.ReplyAsync(e.Finding.Body, "finding", e.Finding.Payload, ct);
        await Pause(ct);
        await w.ReplyAsync($"Indicators from incident {id}.", "ioc", new { indicators = e.Iocs }, ct);
        await Pause(ct);
        var cls = e.Verdict.GetProperty("classification").GetString();
        await w.ReplyAsync($"Verdict: **{cls}** (confidence {e.Verdict.GetProperty("confidence").GetDouble():0.##}).", "verdict", e.Verdict, ct);
        if (e.Question is { } q) await w.ReplyAsync(q, "question", ct: ct);
        if (e.Action is { } a)
        {
            await Pause(ct);
            var r = await w.Board.RequestActionAsync(new ActionRequest(a.Kind, a.Params, a.Justification, id, w.ThreadId), ct);
            Console.WriteLine($"[agent] requested {a.Kind} for incident {id}: {r.Status}");
        }
    }

    private Task OnQuestion(WorkItem w, CancellationToken ct) =>
        w.Message.Mentions.Contains(w.Me) ? OnMention(w, ct) : ReleaseUnanswered(w);

    /// <summary>Unmentioned open questions: the scripted agent can't answer, so it hands the claim straight back.</summary>
    private static Task ReleaseUnanswered(WorkItem w)
    {
        w.ReleaseWhenDone();
        return Task.CompletedTask;
    }

    private async Task OnMention(WorkItem w, CancellationToken ct)
    {
        await w.ReplyAsync($"@{w.Message.Author.Handle} {script.MentionReply}", ct: ct);
    }

    private Task Pause(CancellationToken ct) => delay > TimeSpan.Zero ? Task.Delay(delay, ct) : Task.CompletedTask;

    private static async Task Try(Func<Task> f)
    {
        try { await f(); }
        catch (BoardToolException ex) { Console.WriteLine($"[agent] lookup failed: {ex.Message}"); }
    }
}
