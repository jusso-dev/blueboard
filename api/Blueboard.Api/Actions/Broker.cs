using Blueboard.Contracts;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Npgsql;

namespace Blueboard.Api.Actions;

/// <summary>
/// Request → policy → (human approval) → execute exactly once → post the result. Every step is audited.
/// Destructive actions never run without a decision from a human approver who isn't the requester.
/// </summary>
public sealed class Broker(Db db, Audit audit, BoardService board, MsClient ms, Settings settings, Policy policy, SystemPrincipal system)
{
    private const string Select = """
        select a.id, a.kind, a.params::text as params, a.incident_id, i.graph_id as incident_graph_id, a.request_message_id,
               rp.handle as requested_by, a.justification, a.status, a.requires_approval, a.policy_notes,
               dp.handle as decided_by, a.decided_at, a.decision_note, a.result::text as result, a.error, a.created_at
        from actions a
        join principals rp on rp.id = a.requested_by
        left join principals dp on dp.id = a.decided_by
        left join incidents i on i.id = a.incident_id
        """;

    private static ActionRow Read(NpgsqlDataReader r) => new(
        r.GetGuid(0), r.GetString(1), JsonDocument.Parse(r.GetString(2)).RootElement.Clone(), r.Get<Guid?>("incident_id"), r.Get<string>("incident_graph_id"),
        r.Get<Guid?>("request_message_id"), r.GetString(6), r.GetString(7), r.GetString(8), r.GetBoolean(9), r.GetFieldValue<string[]>(10),
        r.Get<string>("decided_by"), r.Get<DateTimeOffset?>("decided_at"), r.Get<string>("decision_note"),
        r.Get<string>("result") is { } res ? JsonDocument.Parse(res).RootElement.Clone() : null, r.Get<string>("error"), r.GetFieldValue<DateTimeOffset>(16));

    public async Task<ActionRow?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"{Select} where a.id = @id").With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? Read(r) : null;
    }

    public async Task<IReadOnlyList<ActionRow>> ListAsync(string? status, CancellationToken ct = default)
    {
        await using var cmd = status is null
            ? db.Command($"{Select} order by a.created_at desc limit 100")
            : db.Command($"{Select} where a.status = @s order by a.created_at desc limit 100").With("s", status);
        var list = new List<ActionRow>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(Read(r));
        return list;
    }

    public static IEnumerable<object> CatalogInfo() => Catalog.All.Values.Select(a => new { a.Kind, a.Title, a.Stage, a.Destructive, Params = a.ParamsSchema });

    public async Task<ActionRow> RequestAsync(Principal p, ActionRequest req, CancellationToken ct = default)
    {
        p.Require(Roles.Requester);
        if (req.Justification is not { Length: >= 20 and <= 4000 }) throw new BoardException("justification must be 20–4000 characters, citing evidence");
        var def = Catalog.Get(req.Kind);
        var prms = def.Validate(req.Params);

        var incidentId = await board.ResolveIncidentAsync(req.Incident, ct);
        if (incidentId is null && req.ParentId is { } parent) incidentId = (await board.GetAsync(parent, ct))?.IncidentId;
        IncidentContext? incident = null;
        if (incidentId is { } iid)
        {
            await using var ic = db.Command("select graph_id, data::text from incidents where id = @id").With("id", iid);
            await using var ir = await ic.ExecuteReaderAsync(ct);
            if (await ir.ReadAsync(ct)) incident = new IncidentContext(ir.GetString(0), JsonDocument.Parse(ir.GetString(1)).RootElement.Clone());
        }

        var decision = PolicyEngine.Evaluate(def, prms, incident, policy);
        var status = decision.Outcome switch { Outcome.Reject => "rejected", Outcome.Auto => "approved", _ => "pending_approval" };

        // The action row, its board message and the link between them commit together (issue #4): a crash can't
        // leave an action without its message, or a message without its action.
        var label = status switch { "rejected" => "REJECTED by policy", "approved" => "auto-approved (non-destructive)", _ => "awaiting human approval" };
        var body = $"@{p.Handle} requests **{def.Title}**: {def.Describe(prms)}\n\n> {req.Justification.Replace("\n", "\n> ")}\n\nStatus: **{label}**"
                   + (decision.Notes.Count > 0 ? "\n\nPolicy notes:\n" + string.Join("\n", decision.Notes.Select(n => $"- {n}")) : "");
        var sys = await system.GetAsync(ct);
        Guid actionId;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using (var ins = new NpgsqlCommand("""
                insert into actions (kind, params, incident_id, requested_by, justification, status, requires_approval, policy_notes)
                values (@k, @p, @i, @r, @j, @s, @ra, @n) returning id
                """, conn, tx).With("k", def.Kind).WithJson("p", prms).With("i", incidentId).With("r", p.Id).With("j", req.Justification)
                .With("s", status).With("ra", decision.Outcome == Outcome.NeedsApproval).With("n", decision.Notes.ToArray()))
                actionId = (Guid)(await ins.ExecuteScalarAsync(ct))!;
            var msgId = await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment", body, "action_request",
                Json.Element(new { action_id = actionId, kind = def.Kind, @params = prms, status, policy_notes = decision.Notes }), null, incidentId?.ToString()), system: true, ct);
            await using (var up = new NpgsqlCommand("update actions set request_message_id = @m where id = @id", conn, tx).With("m", msgId).With("id", actionId))
                await up.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(p.Id, "action.requested", actionId.ToString(), new { kind = def.Kind, @params = prms, outcome = decision.Outcome.ToString(), notes = decision.Notes }, ct);

        if (status == "approved") await ExecuteAsync(actionId, ct);
        return (await GetAsync(actionId, ct))!;
    }

    /// <summary>Human decision: approver role, a person (never an agent), and not the requester.</summary>
    public async Task<ActionRow> DecideAsync(Principal p, Guid id, string decision, string? note, CancellationToken ct = default)
    {
        if (!p.IsHuman || !p.Has(Roles.Approver)) throw BoardException.Forbidden("only human approvers can decide actions");
        if (decision is not ("approve" or "deny")) throw new BoardException("decision must be approve or deny");
        if (note is { Length: > 2000 }) throw new BoardException("note too long");
        var status = decision == "approve" ? "approved" : "denied";
        var sys = await system.GetAsync(ct);
        // The decision and its status message commit together (issue #4).
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using (var cmd = new NpgsqlCommand("""
                update actions set status = @s, decided_by = @p, decided_at = now(), decision_note = @n, updated_at = now()
                where id = @id and status = 'pending_approval' and requested_by <> @p returning kind, request_message_id, incident_id
                """, conn, tx).With("s", status).With("p", p.Id).With("n", note).With("id", id))
            {
                string kind; Guid? requestMessageId; Guid? incidentId;
                await using (var r = await cmd.ExecuteReaderAsync(ct))
                {
                    if (!await r.ReadAsync(ct))
                    {
                        await r.DisposeAsync();
                        await tx.RollbackAsync(ct);
                        var a = await GetAsync(id, ct) ?? throw BoardException.NotFound("action");
                        if (a.RequestedBy == p.Handle) throw BoardException.Forbidden("you cannot approve your own request");
                        throw BoardException.Conflict($"action is {a.Status}");
                    }
                    kind = r.GetString(0); requestMessageId = r.Get<Guid?>("request_message_id"); incidentId = r.Get<Guid?>("incident_id");
                }
                var requester = (await GetAsync(id, ct))!.RequestedBy;
                await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment",
                    $"@{p.Handle} **{status}** {Catalog.Get(kind).Title}{(note is null ? "" : $": {note}")} (requested by @{requester})",
                    "status", Json.Element(new { state = $"action_{status}", action_id = id }), requestMessageId, incidentId?.ToString()), system: true, ct);
            }
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(p.Id, $"action.{status}", id.ToString(), new { note }, ct);
        if (status == "approved") await ExecuteAsync(id, ct);
        return (await GetAsync(id, ct))!;
    }

    /// <summary>Run an approved action exactly once (claimed by the approved → running transition).</summary>
    public async Task ExecuteAsync(Guid id, CancellationToken ct = default)
    {
        await using (var claim = db.Command("update actions set status = 'running', started_at = now(), updated_at = now() where id = @id and status = 'approved' returning id").With("id", id))
            if (await claim.ExecuteScalarAsync(ct) is null) return;
        var a = (await GetAsync(id, ct))!;
        var def = Catalog.Get(a.Kind);
        var comment = $"blueboard action {id} for incident {a.IncidentGraphId ?? "n/a"}, requested by {a.RequestedBy}"
                      + (a.DecidedBy is null ? " (auto-approved)" : $", approved by {a.DecidedBy}") + $": {a.Justification}";
        string status;
        object? result = null;
        string? error = null;
        JsonObject? prms = null;
        try
        {
            prms = def.Validate(a.Params); // never run a write from unchecked stored JSON
            result = settings.BrokerExecute ? await def.Run(ms, prms, comment, ct) : new { dry_run = true, would = def.Describe(prms) };
            status = "succeeded";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            status = "failed";
            error = ex.Message;
        }
        await using (var up = db.Command("update actions set status = @s, result = @r, error = @e, finished_at = now(), updated_at = now() where id = @id")
                         .With("s", status).WithJson("r", result).With("e", error).With("id", id))
            await up.ExecuteNonQueryAsync(ct);
        await audit.WriteAsync(null, $"action.{status}", id.ToString(), new { error }, ct);
        var text = status == "succeeded"
            ? $"**{def.Title}** {(settings.BrokerExecute ? "completed" : "completed (dry run: BROKER_EXECUTE is off)")}: {def.Describe(prms!)}"
            : $"**{def.Title}** failed: {error}";
        await board.PostAsync(await system.GetAsync(ct), new PostInput("containment", text, "action_result",
            Json.Element(new { action_id = id, status, error }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
    }

    /// <summary>
    /// Recovery for actions a crash left behind. approved &gt; 1 min: never started, safe to run.
    /// running &gt; 10 min: may or may not have reached Defender, so never re-run blindly: mark failed and say so.
    /// </summary>
    public async Task<(int Resumed, int Interrupted)> RecoverAsync(CancellationToken ct = default)
    {
        var stuck = new List<Guid>();
        await using (var cmd = db.Command("select id from actions where status = 'approved' and updated_at < now() - interval '1 minute' order by created_at limit 20"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) stuck.Add(r.GetGuid(0));
        foreach (var id in stuck) await ExecuteAsync(id, ct);

        var stale = new List<Guid>();
        await using (var cmd = db.Command("""
            update actions set status = 'failed', finished_at = now(), updated_at = now(),
                   error = 'interrupted while running: outcome unknown, check Defender before re-requesting'
            where status = 'running' and coalesce(started_at, updated_at) < now() - interval '10 minutes' returning id
            """))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) stale.Add(r.GetGuid(0));
        foreach (var id in stale)
        {
            var a = (await GetAsync(id, ct))!;
            await audit.WriteAsync(null, "action.interrupted", id.ToString(), null, ct);
            await board.PostAsync(await system.GetAsync(ct), new PostInput("containment",
                $"**{Catalog.Get(a.Kind).Title}** was interrupted while running. Its outcome is unknown: check Defender before requesting it again.",
                "action_result", Json.Element(new { action_id = id, status = "failed", error = a.Error }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
        }
        // Actions filed before requests became transactional could be left without their board message.
        var orphans = new List<Guid>();
        await using (var cmd = db.Command("select id from actions where request_message_id is null and created_at < now() - interval '1 minute' order by created_at limit 20"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) orphans.Add(r.GetGuid(0));
        foreach (var id in orphans)
        {
            var a = (await GetAsync(id, ct))!;
            var def = Catalog.Get(a.Kind);
            var msg = await board.PostAsync(await system.GetAsync(ct), new PostInput("containment",
                $"@{a.RequestedBy} requested **{def.Title}** (status: {a.Status}). This request was recovered after an interruption.",
                "action_request", Json.Element(new { action_id = id, kind = a.Kind, @params = a.Params, status = a.Status, policy_notes = a.PolicyNotes }),
                null, a.IncidentId?.ToString()), system: true, ct);
            await using var up = db.Command("update actions set request_message_id = @m where id = @id and request_message_id is null").With("m", msg.Id).With("id", id);
            await up.ExecuteNonQueryAsync(ct);
        }
        return (stuck.Count, stale.Count);
    }
}

/// <summary>The board's own principal ("board"), used for system messages.</summary>
public sealed class SystemPrincipal(Db db)
{
    private Principal? _cached;

    public async Task<Principal> GetAsync(CancellationToken ct = default)
    {
        if (_cached is not null) return _cached;
        await using var cmd = db.Command("select id, handle, display_name, kind, roles from principals where handle = 'board'");
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) throw new InvalidOperationException("board system principal missing; run migrations");
        return _cached = new Principal(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<string[]>(4));
    }
}
