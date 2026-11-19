using Blueboard.Contracts;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Npgsql;

namespace Blueboard.Api.Actions;

public static class ActionStatus
{
    /// <summary>Waiting for a human: no approval yet, or 1 of 2.</summary>
    public static readonly string[] Open = ["pending_approval", "approved_once"];
}

/// <summary>
/// Request → policy → (human approval) → execute exactly once → post the result. Every step is audited.
/// Destructive actions never run without a decision from a human approver who isn't the requester.
/// </summary>
public sealed class Broker(Db db, Audit audit, BoardService board, MsClient ms, Settings settings, Policy policy, SystemPrincipal system, RateLimiter? limiter = null)
{
    private const string Select = """
        select a.id, a.kind, a.params::text as params, a.incident_id, i.graph_id as incident_graph_id, a.request_message_id,
               rp.handle as requested_by, a.justification, a.status, a.requires_approval, a.policy_notes,
               dp.handle as decided_by, a.decided_at, a.decision_note, a.result::text as result, a.error, a.created_at,
               a.expires_at, a.approvals_required,
               array(select ap.handle from action_approvals x join principals ap on ap.id = x.approver_id where x.action_id = a.id order by x.at) as approvals
        from actions a
        join principals rp on rp.id = a.requested_by
        left join principals dp on dp.id = a.decided_by
        left join incidents i on i.id = a.incident_id
        """;

    private static ActionRow Read(NpgsqlDataReader r) => new(
        r.GetGuid(0), r.GetString(1), JsonDocument.Parse(r.GetString(2)).RootElement.Clone(), r.Get<Guid?>("incident_id"), r.Get<string>("incident_graph_id"),
        r.Get<Guid?>("request_message_id"), r.GetString(6), r.GetString(7), r.GetString(8), r.GetBoolean(9), r.GetFieldValue<string[]>(10),
        r.Get<string>("decided_by"), r.Get<DateTimeOffset?>("decided_at"), r.Get<string>("decision_note"),
        r.Get<string>("result") is { } res ? JsonDocument.Parse(res).RootElement.Clone() : null, r.Get<string>("error"), r.GetFieldValue<DateTimeOffset>(16),
        r.Get<DateTimeOffset?>("expires_at"), r.GetInt32(18), r.GetFieldValue<string[]>(19));

    public async Task<ActionRow?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"{Select} where a.id = @id").With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? Read(r) : null;
    }

    /// <summary>Actions, newest first. status: one status, or "open" for everything waiting on a human (pending or 1 of 2).</summary>
    public async Task<IReadOnlyList<ActionRow>> ListAsync(string? status, CancellationToken ct = default)
    {
        await using var cmd = status switch
        {
            null => db.Command($"{Select} order by a.created_at desc limit 100"),
            "open" => db.Command($"{Select} where a.status = any(@s) order by a.created_at desc limit 100").With("s", ActionStatus.Open),
            _ => db.Command($"{Select} where a.status = @s order by a.created_at desc limit 100").With("s", status),
        };
        var list = new List<ActionRow>();
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) list.Add(Read(r));

        // Approvers of confirm_target kinds are asked to type the target back: tell the UI which name to ask for.
        var incidents = new Dictionary<Guid, IncidentContext?>();
        for (var i = 0; i < list.Count; i++)
        {
            var a = list[i];
            if (!ActionStatus.Open.Contains(a.Status) || !policy.ConfirmsTarget(a.Kind)) continue;
            IncidentContext? inc = null;
            if (a.IncidentId is { } iid && !incidents.TryGetValue(iid, out inc)) incidents[iid] = inc = await LoadIncidentAsync(iid, ct);
            list[i] = a with { ConfirmPrompt = ConfirmNames(a, inc).FirstOrDefault() };
        }
        return list;
    }

    private static IReadOnlyList<string> ConfirmNames(ActionRow a, IncidentContext? incident)
    {
        var def = Catalog.Get(a.Kind);
        return PolicyEngine.ConfirmNames(def, def.Validate(a.Params), incident);
    }

    /// <summary>The catalogue, with each kind's target type and, given a policy, how that policy treats it.</summary>
    public static IEnumerable<object> CatalogInfo(Policy? policy = null) => Catalog.All.Values.Select(a => new
    {
        a.Kind, a.Title, a.Stage, a.Destructive, Target = Catalog.TargetType(a.Kind), Params = a.ParamsSchema,
        Mode = policy is null ? null : PolicyReport.ModeOf(a.Kind, policy),
    });

    private async Task<IncidentContext?> LoadIncidentAsync(Guid id, CancellationToken ct)
    {
        await using var ic = db.Command("select graph_id, data::text from incidents where id = @id").With("id", id);
        await using var ir = await ic.ExecuteReaderAsync(ct);
        return await ir.ReadAsync(ct) ? new IncidentContext(ir.GetString(0), JsonDocument.Parse(ir.GetString(1)).RootElement.Clone()) : null;
    }

    /// <summary>Validate params and resolve the linked incident: the shared first half of request, preview and simulate.</summary>
    private async Task<(ActionDef Def, JsonObject Params, Guid? IncidentId, IncidentContext? Incident)> PrepareAsync(
        string kind, JsonElement rawParams, string? incidentRef, Guid? parentId, CancellationToken ct)
    {
        var def = Catalog.Get(kind);
        var prms = def.Validate(rawParams);
        var incidentId = await board.ResolveIncidentAsync(incidentRef, ct);
        if (incidentId is null && parentId is { } parent) incidentId = (await board.GetAsync(parent, ct))?.IncidentId;
        return (def, prms, incidentId, incidentId is { } iid ? await LoadIncidentAsync(iid, ct) : null);
    }

    /// <summary>
    /// What the board would do with this request under the current policy, without filing it. Used by
    /// POST /api/actions/preview and POST /api/policy/simulate. RequestAsync goes through the same PrepareAsync and
    /// PolicyEngine.Assess calls, so a preview always matches the real decision. Callers check roles.
    /// </summary>
    public async Task<Assessment> AssessAsync(PreviewRequest req, CancellationToken ct = default)
    {
        var (def, prms, _, incident) = await PrepareAsync(req.Kind, req.Params, req.Incident, null, ct);
        return PolicyEngine.Assess(def, prms, incident, policy);
    }

    public async Task<ActionRow> RequestAsync(Principal p, ActionRequest req, CancellationToken ct = default)
    {
        p.Require(Roles.Requester);
        if (limiter is not null) await limiter.TakeAsync(p, "action_request", ct);
        if (req.Justification is not { Length: >= 20 and <= 4000 }) throw new BoardException("justification must be 20–4000 characters, citing evidence");
        var (def, prms, incidentId, incident) = await PrepareAsync(req.Kind, req.Params, req.Incident, req.ParentId, ct);
        var decision = PolicyEngine.Assess(def, prms, incident, policy);
        var status = decision.Status;

        // The action row, its board message and the link between them commit together (issue #4): a crash can't
        // leave an action without its message, or a message without its action.
        var label = status switch
        {
            "rejected" => "REJECTED by policy",
            "approved" => "auto-approved (non-destructive)",
            _ => decision.ApprovalsRequired == 2 ? "awaiting two human approvals" : "awaiting human approval",
        };
        var body = $"@{p.Handle} requests **{def.Title}**: {def.Describe(prms)}\n\n> {req.Justification.Replace("\n", "\n> ")}\n\nStatus: **{label}**"
                   + (decision.Notes.Count > 0 ? "\n\nPolicy notes:\n" + string.Join("\n", decision.Notes.Select(n => $"- {n}")) : "");
        var sys = await system.GetAsync(ct);
        Guid actionId;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            if (status == "pending_approval" && incidentId is { } capped) await EnforcePendingCapAsync(conn, tx, p, capped, incident?.GraphId ?? capped.ToString(), ct);
            var needsApproval = decision.Outcome == Outcome.NeedsApproval;
            await using (var ins = new NpgsqlCommand("""
                insert into actions (kind, params, incident_id, requested_by, justification, status, requires_approval, policy_notes, expires_at, approvals_required)
                values (@k, @p, @i, @r, @j, @s, @ra, @n, case when @ra then now() + make_interval(secs => @exp) end, @ar) returning id
                """, conn, tx).With("k", def.Kind).WithJson("p", prms).With("i", incidentId).With("r", p.Id).With("j", req.Justification)
                .With("s", status).With("ra", needsApproval).With("n", decision.Notes.ToArray())
                .With("exp", decision.ExpiresInHours * 3600).With("ar", Math.Max(1, decision.ApprovalsRequired)))
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

    /// <summary>
    /// Too many requests already waiting on one incident (issue #5), so a looping agent can't flood the approval queue.
    /// Locks the incident row so concurrent requests count correctly.
    /// </summary>
    private async Task EnforcePendingCapAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Principal p, Guid incidentId, string graphId, CancellationToken ct)
    {
        await using (var lk = new NpgsqlCommand("select 1 from incidents where id = @i for update", conn, tx).With("i", incidentId))
            await lk.ExecuteNonQueryAsync(ct);
        await using var cnt = new NpgsqlCommand("select count(*)::int from actions where incident_id = @i and status = any(@open)", conn, tx)
            .With("i", incidentId).With("open", ActionStatus.Open);
        var open = (int)(await cnt.ExecuteScalarAsync(ct))!;
        var cap = policy.Limits.PendingActionsPerIncident;
        if (open < cap) return;
        await audit.WriteAsync(p.Id, "limit.hit", p.Handle, new { bucket = "pending_actions_per_incident", incident = graphId, limit = cap }, ct);
        throw new BoardException($"incident {graphId} already has {open} actions waiting for approval (limit {cap}); decide or let some expire first", 429)
        {
            Bucket = "pending_actions_per_incident",
            RetryAfterSeconds = 60,
        };
    }

    /// <summary>
    /// Human decision: approver role, a person (never an agent), and not the requester. Before approving, the board checks
    /// that the request hasn't expired, asks for the target typed back (confirm_target kinds) and re-runs policy against
    /// the current policy and evidence. Kinds in require_two_approvers need two different people: the first approval
    /// moves the action to approved_once, the second runs it.
    /// </summary>
    public async Task<ActionRow> DecideAsync(Principal p, Guid id, string decision, string? note, CancellationToken ct = default, string? confirm = null)
    {
        if (!p.IsHuman || !p.Has(Roles.Approver)) throw BoardException.Forbidden("only human approvers can decide actions");
        if (decision is not ("approve" or "deny")) throw new BoardException("decision must be approve or deny");
        if (note is { Length: > 2000 }) throw new BoardException("note too long");

        var a = await GetAsync(id, ct) ?? throw BoardException.NotFound("action");
        if (a.RequestedBy == p.Handle) throw BoardException.Forbidden("you cannot approve your own request");
        if (!ActionStatus.Open.Contains(a.Status)) throw BoardException.Conflict($"action is {a.Status}");
        if (a.ExpiresAt is { } exp && exp <= DateTimeOffset.UtcNow)
        {
            await ExpireOneAsync(id, ct);
            throw BoardException.Conflict("action is expired");
        }

        var def = Catalog.Get(a.Kind);
        var required = Math.Max(a.ApprovalsRequired, policy.ApprovalsFor(a.Kind));
        if (decision == "approve")
        {
            if (a.Approvals?.Contains(p.Handle) == true) throw BoardException.Conflict("you already approved this action; a different approver must complete it");
            var incident = a.IncidentId is { } iid ? await LoadIncidentAsync(iid, ct) : null;
            if (policy.ConfirmsTarget(a.Kind))
            {
                var names = ConfirmNames(a, incident);
                if (confirm is null || !names.Contains(confirm.Trim(), StringComparer.OrdinalIgnoreCase))
                    throw new BoardException($"type the target ({names.FirstOrDefault()}) to confirm this approval");
            }
            // The situation may have changed since the request (policy reloaded, evidence updated): re-run policy now.
            var now = PolicyEngine.Assess(def, def.Validate(a.Params), incident, policy);
            if (now.Outcome == Outcome.Reject)
            {
                await RejectOnRecheckAsync(p, a, now.Notes[0], ct);
                throw BoardException.Conflict($"policy now rejects this action: {now.Notes[0]}");
            }
        }

        var sys = await system.GetAsync(ct);
        string status;
        int count = 0;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            // Lock the row: concurrent approvers queue here, so two people can't both be "1 of 2".
            await using (var lk = new NpgsqlCommand("""
                select 1 from actions where id = @id and status = any(@open) and requested_by <> @p
                  and (expires_at is null or expires_at > now()) for update
                """, conn, tx).With("id", id).With("open", ActionStatus.Open).With("p", p.Id))
                if (await lk.ExecuteScalarAsync(ct) is null)
                {
                    await tx.RollbackAsync(ct);
                    var latest = (await GetAsync(id, ct))!;
                    throw BoardException.Conflict(ActionStatus.Open.Contains(latest.Status) ? "action is expired" : $"action is {latest.Status}");
                }

            if (decision == "approve")
            {
                await using (var ins = new NpgsqlCommand("insert into action_approvals (action_id, approver_id, note) values (@id, @p, @n) on conflict do nothing", conn, tx)
                                 .With("id", id).With("p", p.Id).With("n", note))
                    if (await ins.ExecuteNonQueryAsync(ct) == 0)
                    {
                        await tx.RollbackAsync(ct);
                        throw BoardException.Conflict("you already approved this action; a different approver must complete it");
                    }
                await using var cnt = new NpgsqlCommand("select count(*)::int from action_approvals where action_id = @id", conn, tx).With("id", id);
                count = (int)(await cnt.ExecuteScalarAsync(ct))!;
            }
            status = decision == "deny" ? "denied" : count >= required ? "approved" : "approved_once";

            await using (var up = new NpgsqlCommand(status == "approved_once"
                    ? "update actions set status = @s, approvals_required = @req, updated_at = now() where id = @id"
                    : "update actions set status = @s, approvals_required = @req, decided_by = @p, decided_at = now(), decision_note = @n, updated_at = now() where id = @id",
                    conn, tx).With("s", status).With("req", required).With("p", p.Id).With("n", note).With("id", id))
                await up.ExecuteNonQueryAsync(ct);

            var suffix = note is null ? "" : $": {note}";
            var text = status == "approved_once"
                ? $"@{p.Handle} **approved** {def.Title} (1 of {required}){suffix}. A different approver must complete it (requested by @{a.RequestedBy})"
                : $"@{p.Handle} **{status}** {def.Title}{(required > 1 && status == "approved" ? $" ({count} of {required})" : "")}{suffix} (requested by @{a.RequestedBy})";
            // The decision and its status message commit together (issue #4).
            await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment", text,
                "status", Json.Element(new { state = $"action_{status}", action_id = id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(p.Id, $"action.{status}", id.ToString(), new { note, approvals = count, approvals_required = required }, ct);
        if (status == "approved") await ExecuteAsync(id, ct);
        return (await GetAsync(id, ct))!;
    }

    /// <summary>Policy (or the evidence) changed since the request and now says no: close the request as rejected.</summary>
    private async Task RejectOnRecheckAsync(Principal p, ActionRow a, string reason, CancellationToken ct)
    {
        var sys = await system.GetAsync(ct);
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using (var up = new NpgsqlCommand("""
                update actions set status = 'rejected', policy_notes = array_append(policy_notes, @why), updated_at = now()
                where id = @id and status = any(@open)
                """, conn, tx).With("why", $"rejected when re-checked at approval: {reason}").With("id", a.Id).With("open", ActionStatus.Open))
                if (await up.ExecuteNonQueryAsync(ct) == 0) return;
            await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment",
                $"**{Catalog.Get(a.Kind).Title}** is now **rejected by policy**: {reason}. @{a.RequestedBy}'s request was re-checked when @{p.Handle} tried to approve it.",
                "status", Json.Element(new { state = "action_rejected", action_id = a.Id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(p.Id, "action.rejected_on_recheck", a.Id.ToString(), new { reason }, ct);
    }

    /// <summary>Expire one open action whose time is up: status, a reply in its thread that @mentions the requester, an audit row.</summary>
    private async Task<bool> ExpireOneAsync(Guid id, CancellationToken ct)
    {
        var sys = await system.GetAsync(ct);
        ActionRow a;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using (var up = new NpgsqlCommand("""
                update actions set status = 'expired', updated_at = now()
                where id = @id and status = any(@open) and expires_at <= now() returning id
                """, conn, tx).With("id", id).With("open", ActionStatus.Open))
                if (await up.ExecuteScalarAsync(ct) is null) return false;
            a = (await GetAsync(id, ct))!; // other connection: still shows the pre-update row, which is all we need
            await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment",
                $"**{Catalog.Get(a.Kind).Title}** **expired** without {(a.Approvals is { Length: > 0 } ? "a second approval" : "a decision")}. @{a.RequestedBy} can request it again if it's still needed.",
                "status", Json.Element(new { state = "action_expired", action_id = id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(null, "action.expired", id.ToString(), new { kind = a.Kind, expires_at = a.ExpiresAt, approvals = a.Approvals }, ct);
        return true;
    }

    /// <summary>Expiry sweep, run by the recovery timer: open actions past expires_at become expired.</summary>
    public async Task<int> ExpireDueAsync(CancellationToken ct = default)
    {
        var due = new List<Guid>();
        await using (var cmd = db.Command("select id from actions where status = any(@open) and expires_at <= now() order by expires_at limit 100").With("open", ActionStatus.Open))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) due.Add(r.GetGuid(0));
        var n = 0;
        foreach (var id in due) if (await ExpireOneAsync(id, ct)) n++;
        return n;
    }

    /// <summary>Run an approved action exactly once (claimed by the approved → running transition).</summary>
    public async Task ExecuteAsync(Guid id, CancellationToken ct = default)
    {
        await using (var claim = db.Command("update actions set status = 'running', started_at = now(), updated_at = now() where id = @id and status = 'approved' returning id").With("id", id))
            if (await claim.ExecuteScalarAsync(ct) is null) return;
        var a = (await GetAsync(id, ct))!;
        var def = Catalog.Get(a.Kind);
        var approvers = a.Approvals is { Length: > 0 } list ? string.Join(" and ", list) : a.DecidedBy;
        var comment = $"blueboard action {id} for incident {a.IncidentGraphId ?? "n/a"}, requested by {a.RequestedBy}"
                      + (approvers is null ? " (auto-approved)" : $", approved by {approvers}") + $": {a.Justification}";
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
