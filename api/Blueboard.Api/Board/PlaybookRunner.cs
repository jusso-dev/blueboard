using Blueboard.Contracts;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Blueboard.Api.Board;

/// <summary>
/// Attaches the first matching playbook to a new incident and posts its steps as claimable `question` replies in the
/// incident thread (payload.checklist). A step with `after` is posted only once every prerequisite step is done.
/// Claiming and completing steps is the ordinary claim flow; this class never runs or requests an action.
/// </summary>
public sealed class PlaybookRunner(Db db, BoardService board, SystemPrincipal system, PlaybookSet playbooks, PolicyStore? triggers = null)
{
    /// <summary>
    /// Called by ingest when an incident is first seen. Returns the attached playbook id, or null. With the policy store
    /// wired, the admin-editable trigger rules decide (file triggers from each playbook's match, plus custom ones).
    /// </summary>
    public async Task<string?> AttachAsync(Guid incidentId, JsonElement incident, Guid? rootMessageId, CancellationToken ct = default)
    {
        var pb = triggers is null ? playbooks.Match(incident) : await triggers.MatchPlaybookAsync(incident, ct) is { } id ? playbooks.Get(id) : null;
        if (pb is null) return null;
        await using (var cmd = db.Command("""
            insert into incident_playbooks (incident_id, playbook_id, root_message_id) values (@i, @p, @r)
            on conflict (incident_id) do nothing returning incident_id
            """).With("i", incidentId).With("p", pb.Id).With("r", rootMessageId))
            if (await cmd.ExecuteScalarAsync(ct) is null) return null;
        await UnlockAsync(incidentId, ct);
        return pb.Id;
    }

    /// <summary>Manually attach a playbook to an incident that doesn't have one yet (analyst or agent via MCP/REST).</summary>
    public async Task<object> AttachByIdAsync(Principal caller, string incidentRef, string playbookId, CancellationToken ct = default)
    {
        caller.Require(Roles.Poster);
        var pb = playbooks.Get(playbookId) ?? throw BoardException.NotFound($"playbook '{playbookId}'");
        if (pb.Scope != Playbooks.IncidentScope)
            throw new BoardException($"playbook '{playbookId}' runs from a threat intel finding (start_ti_playbook), not on an incident");
        var incidentId = await board.ResolveIncidentAsync(incidentRef, ct) ?? throw BoardException.NotFound("incident");
        Guid? root = null;
        await using (var rc = db.Command("""
            select m.id from messages m join channels c on c.id = m.channel_id
            where m.incident_id = @i and m.type = 'incident' and m.parent_id is null and c.name = 'incidents'
            order by m.seq asc limit 1
            """).With("i", incidentId))
            root = await rc.ExecuteScalarAsync(ct) as Guid?;
        await using (var cmd = db.Command("""
            insert into incident_playbooks (incident_id, playbook_id, root_message_id) values (@i, @p, @r)
            on conflict (incident_id) do nothing returning incident_id
            """).With("i", incidentId).With("p", pb.Id).With("r", root))
            if (await cmd.ExecuteScalarAsync(ct) is null)
                throw BoardException.Conflict("incident already has a playbook attached");
        var posted = await UnlockAsync(incidentId, ct);
        return new { incident_id = incidentId, playbook_id = pb.Id, title = pb.Title, steps_posted = posted, total_steps = pb.Steps.Count };
    }

    /// <summary>Post every step whose prerequisites are done and that isn't on the board yet. Safe to run concurrently.</summary>
    public async Task<int> UnlockAsync(Guid incidentId, CancellationToken ct = default)
    {
        string playbookId;
        Guid? root;
        await using (var cmd = db.Command("select playbook_id, root_message_id from incident_playbooks where incident_id = @i and not all_posted").With("i", incidentId))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (!await r.ReadAsync(ct)) return 0;
            playbookId = r.GetString(0);
            root = r.Get<Guid?>("root_message_id");
        }
        if (playbooks.Get(playbookId) is not { } pb) return 0; // the file was removed or failed validation after attaching

        var states = await StepStatesAsync(incidentId, pb.Id, ct);
        var posted = 0;
        foreach (var step in Unlocked(pb, states))
        {
            try
            {
                await board.PostAsync(await system.GetAsync(ct), StepPost(pb, step, root, incidentId), system: true, ct);
                states[step.Id] = "open";
                posted++;
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                states[step.Id] = "open"; // another worker posted it first
            }
        }
        if (states.Count >= pb.Steps.Count)
        {
            await using var done = db.Command("update incident_playbooks set all_posted = true where incident_id = @i").With("i", incidentId);
            await done.ExecuteNonQueryAsync(ct);
        }
        return posted;
    }

    /// <summary>Timer sweep: unlock steps on every incident (and threat intel playbook run) that still has hidden ones.</summary>
    public async Task<int> UnlockPendingAsync(CancellationToken ct = default)
    {
        var ids = new List<Guid>();
        await using (var cmd = db.Command("select incident_id from incident_playbooks where not all_posted order by attached_at limit 500"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) ids.Add(r.GetGuid(0));
        var posted = 0;
        foreach (var id in ids) posted += await UnlockAsync(id, ct);
        var runs = new List<Guid>();
        await using (var cmd = db.Command("select id from ti_playbook_runs where not all_posted order by started_at limit 500"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) runs.Add(r.GetGuid(0));
        foreach (var run in runs) posted += await UnlockRunAsync(run, ct);
        return posted;
    }

    /// <summary>After a claim settles: if it was a checklist step, its dependants may now be unlocked.</summary>
    public async Task AfterSettleAsync(Message m, CancellationToken ct = default)
    {
        if (m.ClaimState != "done" || !IsChecklist(m.Payload)) return;
        if (m.IncidentId is { } id) await UnlockAsync(id, ct);
        else if (RunId(m.Payload) is { } run) await UnlockRunAsync(run, ct);
    }

    /// <summary>The intel playbook run a checklist step belongs to (payload.checklist.run), or null for incident steps.</summary>
    public static Guid? RunId(JsonElement? payload) =>
        payload is { ValueKind: JsonValueKind.Object } p && p.TryGetProperty("checklist", out var c) && c.ValueKind == JsonValueKind.Object
        && c.TryGetProperty("run", out var r) && r.ValueKind == JsonValueKind.String && Guid.TryParse(r.GetString(), out var g) ? g : null;

    // ── intel-scoped playbooks: run from a threat intel finding, with no incident ─────────────────

    /// <summary>
    /// Start an intel playbook (scope: intel) for a threat intel finding. The board posts a root status in #intel and
    /// the steps as claimable questions in that thread, the same claim/complete flow as incident checklists. One run
    /// per finding and playbook: a second call returns the existing run.
    /// </summary>
    public async Task<TiPlaybookRun> StartForTiFindingAsync(Principal caller, Guid tiFindingId, string? playbookId, CancellationToken ct = default)
    {
        caller.Require(Roles.Poster);
        var id = playbookId ?? DefaultIntelPlaybook;
        var pb = playbooks.Get(id) ?? throw BoardException.NotFound($"playbook '{id}'");
        if (pb.Scope != Playbooks.IntelScope) throw new BoardException($"playbook '{id}' runs on incidents (attach_playbook), not from a threat intel finding");

        string title, severity;
        string[] cves;
        await using (var fc = db.Command("select title, severity, cves from ti_findings where id = @id").With("id", tiFindingId))
        await using (var fr = await fc.ExecuteReaderAsync(ct))
        {
            if (!await fr.ReadAsync(ct)) throw BoardException.NotFound("threat intel finding");
            (title, severity, cves) = (fr.GetString(0), fr.GetString(1), fr.GetFieldValue<string[]>(2));
        }

        Guid runId;
        bool existing;
        await using (var ins = db.Command("""
            insert into ti_playbook_runs (ti_finding_id, playbook_id, started_by) values (@f, @p, @by)
            on conflict (ti_finding_id, playbook_id) do nothing returning id
            """).With("f", tiFindingId).With("p", pb.Id).With("by", caller.Id))
        {
            var created = await ins.ExecuteScalarAsync(ct) as Guid?;
            existing = created is null;
            if (created is { } c) runId = c;
            else
            {
                await using var sel = db.Command("select id from ti_playbook_runs where ti_finding_id = @f and playbook_id = @p").With("f", tiFindingId).With("p", pb.Id);
                runId = (Guid)(await sel.ExecuteScalarAsync(ct))!;
            }
        }

        if (!existing)
        {
            var safeTitle = IncidentSummary.Md(title);
            var body = $"**{pb.Title}** started by @{caller.Handle} for threat intel finding [{severity.ToUpperInvariant()}] {safeTitle}"
                       + (cves.Length > 0 ? $" ({string.Join(", ", cves.Take(10))})" : "")
                       + ".\n\nClaim each step below and mark it done. The steps never run an action: detections and blocks are requested and approved as usual.";
            var root = await board.PostAsync(await system.GetAsync(ct), new PostInput("intel", body, "status",
                Json.Element(new { state = "ti_playbook_started", ti_finding_id = tiFindingId, playbook = pb.Id, run = runId }), null, null), system: true, ct);
            await using var up = db.Command("update ti_playbook_runs set root_message_id = @r where id = @id").With("r", root.Id).With("id", runId);
            await up.ExecuteNonQueryAsync(ct);
            await new Audit(db).WriteAsync(caller.Id, "ti.playbook_started", tiFindingId.ToString(), new { playbook = pb.Id, run = runId }, ct);
        }
        var posted = await UnlockRunAsync(runId, ct);
        Guid? rootId;
        await using (var rc = db.Command("select root_message_id from ti_playbook_runs where id = @id").With("id", runId))
            rootId = await rc.ExecuteScalarAsync(ct) as Guid?;
        return new TiPlaybookRun(runId, tiFindingId, pb.Id, pb.Title, rootId, posted, pb.Steps.Count, existing);
    }

    public const string DefaultIntelPlaybook = "emerging-threat-detection";

    /// <summary>Post every step of an intel run whose prerequisites are done and that isn't on the board yet.</summary>
    public async Task<int> UnlockRunAsync(Guid runId, CancellationToken ct = default)
    {
        string playbookId;
        Guid? root;
        Guid findingId;
        await using (var cmd = db.Command("select playbook_id, root_message_id, ti_finding_id from ti_playbook_runs where id = @i and not all_posted").With("i", runId))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (!await r.ReadAsync(ct)) return 0;
            playbookId = r.GetString(0);
            root = r.Get<Guid?>("root_message_id");
            findingId = r.GetGuid(2);
        }
        if (playbooks.Get(playbookId) is not { } pb) return 0;

        var states = new Dictionary<string, string>();
        await using (var cmd = db.Command("""
            select m.payload #>> '{checklist,step}', m.claim_state from messages m join principals a on a.id = m.author_id
            where m.incident_id is null and m.type = 'question' and m.payload #>> '{checklist,run}' = @run and a.handle = 'board'
            """).With("run", runId.ToString()))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) states[r.GetString(0)] = r.GetString(1);

        var posted = 0;
        foreach (var step in Unlocked(pb, states))
        {
            try
            {
                await board.PostAsync(await system.GetAsync(ct), RunStepPost(pb, step, root, runId, findingId), system: true, ct);
                states[step.Id] = "open";
                posted++;
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                states[step.Id] = "open";
            }
        }
        if (states.Count >= pb.Steps.Count)
        {
            await using var done = db.Command("update ti_playbook_runs set all_posted = true where id = @i").With("i", runId);
            await done.ExecuteNonQueryAsync(ct);
        }
        return posted;
    }

    internal static PostInput RunStepPost(Playbook pb, PlaybookStep s, Guid? root, Guid runId, Guid tiFindingId)
    {
        var n = pb.Steps.ToList().IndexOf(s) + 1;
        var body = $"**{pb.Title}**, step {n} of {pb.Steps.Count} ({s.Stage}): {s.Title}"
                   + (s.Detail is { Length: > 0 } d ? $"\n\n{d}" : "")
                   + (s.SuggestedAction is { } a ? $"\n\nSuggested action: `{a}`. The playbook doesn't run it: request it if the evidence supports it." : "")
                   + "\n\nClaim this step, then mark it done when it's finished.";
        var payload = Json.Element(new
        {
            checklist = new { playbook = pb.Id, playbook_title = pb.Title, step = s.Id, n, total = pb.Steps.Count, stage = s.Stage, after = s.After, suggested_action = s.SuggestedAction, run = runId.ToString(), ti_finding_id = tiFindingId },
        });
        return new PostInput("intel", body, "question", payload, root, null);
    }

    public static bool IsChecklist(JsonElement? payload) =>
        payload is { ValueKind: JsonValueKind.Object } p && p.TryGetProperty("checklist", out var c) && c.ValueKind == JsonValueKind.Object;

    /// <summary>Steps not yet posted whose prerequisites are all done, in playbook order.</summary>
    public static IEnumerable<PlaybookStep> Unlocked(Playbook pb, IReadOnlyDictionary<string, string> states) =>
        pb.Steps.Where(s => !states.ContainsKey(s.Id) && s.After.All(a => states.GetValueOrDefault(a) == "done")).ToList();

    /// <summary>step id → claim state ("open", "claimed", "done") for the steps already on the board.</summary>
    internal async Task<Dictionary<string, string>> StepStatesAsync(Guid incidentId, string playbookId, CancellationToken ct)
    {
        var states = new Dictionary<string, string>();
        await using var cmd = db.Command("""
            select m.payload #>> '{checklist,step}', m.claim_state from messages m join principals a on a.id = m.author_id
            where m.incident_id = @i and m.type = 'question' and m.payload #>> '{checklist,playbook}' = @p and a.handle = 'board'
            """).With("i", incidentId).With("p", playbookId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) states[r.GetString(0)] = r.GetString(1);
        return states;
    }

    internal static PostInput StepPost(Playbook pb, PlaybookStep s, Guid? root, Guid incidentId)
    {
        var n = pb.Steps.ToList().IndexOf(s) + 1;
        var body = $"**{pb.Title}**, step {n} of {pb.Steps.Count} ({s.Stage}): {s.Title}"
                   + (s.Detail is { Length: > 0 } d ? $"\n\n{d}" : "")
                   + (s.SuggestedAction is { } a ? $"\n\nSuggested action: `{a}`. The playbook doesn't run it: request it from the incident if the evidence supports it." : "")
                   + "\n\nClaim this step, then mark it done when it's finished.";
        var payload = Json.Element(new
        {
            checklist = new { playbook = pb.Id, playbook_title = pb.Title, step = s.Id, n, total = pb.Steps.Count, stage = s.Stage, after = s.After, suggested_action = s.SuggestedAction },
        });
        return new PostInput("incidents", body, "question", payload, root, incidentId.ToString());
    }
}

/// <summary>Logs the playbooks loaded at startup and any files that were skipped.</summary>
public sealed class PlaybooksOnStart(PlaybookSet set, ILogger<PlaybooksOnStart> log) : IHostedService
{
    public Task StartAsync(CancellationToken ct)
    {
        log.LogInformation("loaded {Count} playbooks: {Ids}", set.All.Count, string.Join(", ", set.All.Select(p => p.Id)));
        foreach (var p in set.Problems) log.LogError("playbook {File} skipped: {Error}", p.File, p.Error);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
