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

/// <summary>The broker pause switch, stored in kv_state so every instance sees it on the next execute.</summary>
public sealed record BrokerPause(bool Paused, string? By = null, DateTimeOffset? At = null, string? Reason = null);

/// <summary>
/// Request → policy → (human approval) → execute exactly once → post the result. Every step is audited.
/// Destructive actions never run without a decision from a human approver who isn't the requester.
/// </summary>
public sealed class Broker(Db db, Audit audit, BoardService board, MsClient ms, Settings settings, Policy policy, SystemPrincipal system, RateLimiter? limiter = null,
    PolicyStore? store = null, Agents.AgentFeedback? feedback = null, Connectors.ConnectorHub? connectors = null, Agents.IAgentRiskSource? risk = null)
{
    private readonly KvState _kv = new(db);

    /// <summary>
    /// The policy in force: policy.json ∩ admin overrides (read from the database with a short cache, so every instance
    /// agrees within seconds), or policy.json alone when no override store is wired (tests, tools).
    /// </summary>
    private async Task<Policy> PolicyAsync(CancellationToken ct) => store is null ? policy : await store.CurrentAsync(ct);
    private const string Select = """
        select a.id, a.kind, a.params::text as params, a.incident_id, i.graph_id as incident_graph_id, a.request_message_id,
               rp.handle as requested_by, a.justification, a.status, a.requires_approval, a.policy_notes,
               dp.handle as decided_by, a.decided_at, a.decision_note, a.result::text as result, a.error, a.created_at,
               a.expires_at, a.approvals_required,
               array(select ap.handle from action_approvals x join principals ap on ap.id = x.approver_id where x.action_id = a.id order by x.at) as approvals,
               a.held_at, a.on_behalf_of, a.auto_rule, a.revert_after_minutes, a.revert_at, a.revert_state, a.revert_action_id, a.revert_of
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
        r.Get<DateTimeOffset?>("expires_at"), r.GetInt32(18), r.GetFieldValue<string[]>(19), r.Get<DateTimeOffset?>("held_at"), r.Get<Guid?>("on_behalf_of"),
        r.Get<string>("auto_rule"), r.Get<int?>("revert_after_minutes"), r.Get<DateTimeOffset?>("revert_at"), r.Get<string>("revert_state"),
        r.Get<Guid?>("revert_action_id"), r.Get<Guid?>("revert_of"));

    public async Task<ActionRow?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"{Select} where a.id = @id").With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? Read(r) : null;
    }

    /// <summary>Actions, newest first. status: one status, or "open" for everything waiting on a human (pending or 1 of 2).</summary>
    public Task<IReadOnlyList<ActionRow>> ListAsync(string? status, CancellationToken ct = default) =>
        ListAsync(status, null, ct);

    /// <summary>Actions, newest first, optionally filtered by status and/or linked incident (board UUID or Defender graph id).</summary>
    public async Task<IReadOnlyList<ActionRow>> ListAsync(string? status, string? incident, CancellationToken ct = default)
    {
        var incidentId = await board.ResolveIncidentAsync(incident, ct);
        var where = new List<string>();
        await using var cmd = db.Command("");
        switch (status)
        {
            case null: break;
            case "open": where.Add("a.status = any(@s)"); cmd.With("s", ActionStatus.Open); break;
            case "held": where.Add("a.status = 'approved' and a.held_at is not null"); break;
            default: where.Add("a.status = @s"); cmd.With("s", status); break;
        }
        if (incidentId is { } filterInc) { where.Add("a.incident_id = @inc"); cmd.With("inc", filterInc); }
        cmd.CommandText = $"{Select}{(where.Count > 0 ? " where " + string.Join(" and ", where) : "")} order by a.created_at desc limit 100";
        var list = new List<ActionRow>();
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) list.Add(Read(r));

        // Approvers of confirm_target kinds are asked to type the target back: tell the UI which name to ask for.
        var policy = await PolicyAsync(ct);
        var incidents = new Dictionary<Guid, IncidentContext?>();
        for (var i = 0; i < list.Count; i++)
        {
            var a = list[i];
            var needsConfirm = ActionStatus.Open.Contains(a.Status) || (a.Status == "approved" && a.HeldAt is not null);
            if (!needsConfirm || !policy.ConfirmsTarget(a.Kind)) continue;
            IncidentContext? inc = null;
            if (a.IncidentId is { } iid && !incidents.TryGetValue(iid, out inc)) incidents[iid] = inc = await LoadIncidentAsync(iid, a.RequestedBy, ct);
            // No resolver here: this list is polled every few seconds and must not call Microsoft. The prompt is the
            // evidence name or the id; approval still accepts every resolved alias.
            list[i] = a with { ConfirmPrompt = ConfirmNames(a, inc, null).FirstOrDefault() };
        }
        return list;
    }

    private static IReadOnlyList<string> ConfirmNames(ActionRow a, IncidentContext? incident, ActionFacts? facts)
    {
        var def = Catalog.Get(a.Kind);
        return PolicyEngine.ConfirmNames(def, def.Validate(a.Params), incident, facts);
    }

    /// <summary>The kind's resolver (Resolvers.cs), if it has one: device aliases, back-test binding, the rule to disable.</summary>
    private async Task<ActionFacts?> ActionFactsAsync(ActionDef def, JsonObject prms, DateTimeOffset requestedAt, CancellationToken ct) =>
        def.Resolve is { } resolve ? await resolve(new ResolveContext(db, ms, settings, requestedAt), prms, ct) : null;

    private Task<ActionFacts?> ActionFactsForAsync(ActionRow a, CancellationToken ct)
    {
        var def = Catalog.Get(a.Kind);
        return ActionFactsAsync(def, def.Validate(a.Params), a.CreatedAt, ct);
    }

    /// <summary>The catalogue, with each kind's target type and, given a policy, how that policy treats it.</summary>
    public static IEnumerable<object> CatalogInfo(Policy? policy = null) => Catalog.All.Values.Select(a => new
    {
        a.Kind, a.Title, a.Stage, a.Destructive, Target = Catalog.TargetType(a.Kind), Params = a.ParamsSchema,
        Mode = policy is null ? null : PolicyReport.DisplayModeOf(a.Kind, policy),
    });

    /// <param name="requester">Handle of whoever filed (or would file) the request: their own ioc posts don't count as confirmation.</param>
    private async Task<IncidentContext?> LoadIncidentAsync(Guid id, string requester, CancellationToken ct)
    {
        var inc = await LoadIncidentRowAsync(id, ct);
        // publish_ti_indicator: policy needs the values marked malicious on this incident by someone else (issue #20).
        if (inc is null) return null;
        inc = inc with { MaliciousIocs = await MaliciousIocsAsync(id, requester, ct) };
        // Okta identities linked to this incident's users: cross-IdP protected-user aliases (ConnectorHub, WS5).
        return connectors is null ? inc : inc with { IdentityLinks = await connectors.LinksForIncidentAsync(inc, ct) };
    }

    private async Task<IncidentContext?> LoadIncidentRowAsync(Guid id, CancellationToken ct)
    {
        await using var ic = db.Command("select graph_id, data::text from incidents where id = @id").With("id", id);
        await using var ir = await ic.ExecuteReaderAsync(ct);
        return await ir.ReadAsync(ct) ? new IncidentContext(ir.GetString(0), JsonDocument.Parse(ir.GetString(1)).RootElement.Clone()) : null;
    }

    /// <summary>Validate params and resolve the linked incident: the shared first half of request, preview and simulate.</summary>
    private async Task<(ActionDef Def, JsonObject Params, Guid? IncidentId, IncidentContext? Incident, ActionFacts? Facts)> PrepareAsync(
        string kind, JsonElement rawParams, string? incidentRef, Guid? parentId, string requester, CancellationToken ct)
    {
        var def = Catalog.Get(kind);
        var prms = def.Validate(rawParams);
        if (def.RunConnector is not null)
        {
            if (connectors is null) throw new BoardException($"{kind} needs a connector that is not configured on this board", 409);
            await connectors.PrepareTargetAsync(def, prms, ct); // refreshes the Okta identity link before policy runs
        }
        var incidentId = await board.ResolveIncidentAsync(incidentRef, ct);
        if (incidentId is null && parentId is { } parent) incidentId = (await board.GetAsync(parent, ct))?.IncidentId;
        return (def, prms, incidentId, incidentId is { } iid ? await LoadIncidentAsync(iid, requester, ct) : null, await ActionFactsAsync(def, prms, DateTimeOffset.UtcNow, ct));
    }

    /// <summary>
    /// What the board would do with this request under the current policy, without filing it. Used by
    /// POST /api/actions/preview and POST /api/policy/simulate. RequestAsync goes through the same PrepareAsync and
    /// PolicyEngine.Assess calls, so a preview always matches the real decision. Callers check roles.
    /// </summary>
    public async Task<Assessment> AssessAsync(Principal p, PreviewRequest req, CancellationToken ct = default)
    {
        var (def, prms, incidentId, incident, actionFacts) = await PrepareAsync(req.Kind, req.Params, req.Incident, null, p.Handle, ct);
        var policy = await PolicyAsync(ct);
        var automationFacts = await AutomationFactsAsync(def.Kind, incidentId, p.Handle, null, policy, ct);
        return PolicyEngine.Assess(def, prms, incident, policy, automationFacts, actionFacts: actionFacts);
    }

    /// <summary>
    /// What a conditional rule needs from the database: the newest verdict per author on the incident (people and
    /// agents, never the board), how often the kind already ran on its own, and (only when the rule sets
    /// max_requester_risk) the requester's agent risk score. Null when the kind has no rule in force.
    /// </summary>
    private async Task<AutomationFacts?> AutomationFactsAsync(string kind, Guid? incidentId, string requester, Guid? exclude, Policy policy, CancellationToken ct)
    {
        if (!policy.ActiveRules.TryGetValue(kind, out var rule)) return null;
        var verdicts = new List<VerdictFact>();
        if (incidentId is { } iid)
        {
            await using var vc = db.Command("""
                select distinct on (a.id) a.handle, a.kind, m.payload->>'classification', coalesce((m.payload->>'confidence')::float8, 0)
                from messages m join principals a on a.id = m.author_id
                where m.incident_id = @i and m.type = 'verdict' and a.kind in ('human', 'agent') and a.enabled
                order by a.id, m.seq desc
                """).With("i", iid);
            await using var vr = await vc.ExecuteReaderAsync(ct);
            while (await vr.ReadAsync(ct))
                if (!vr.IsDBNull(2)) verdicts.Add(new VerdictFact(vr.GetString(0), vr.GetString(1), vr.GetString(2), vr.GetDouble(3)));
        }
        var (hour, onIncident) = await AutoRunCountsAsync(db.Command(""), kind, incidentId, exclude, ct);
        var requesterRisk = rule.Spec.MaxRequesterRisk is null ? null : await RequesterRiskAsync(requester, ct);
        return new AutomationFacts(requester, verdicts, hour, onIncident, requesterRisk);
    }

    /// <summary>The requester's stored agent risk score, or null when unknown (no risk source, a person, or not scored yet).</summary>
    private async Task<int?> RequesterRiskAsync(string handle, CancellationToken ct)
    {
        if (risk is null) return null;
        await using var cmd = db.Command("select id from principals where handle = @h").With("h", handle);
        return await cmd.ExecuteScalarAsync(ct) is Guid id && await risk.GetScoreAsync(id, ct) is { } score ? score.Score : null;
    }

    private static async Task<(int Hour, int Incident)> AutoRunCountsAsync(NpgsqlCommand cmd, string kind, Guid? incidentId, Guid? exclude, CancellationToken ct)
    {
        await using (cmd)
        {
            cmd.CommandText = """
                select count(*) filter (where created_at > now() - interval '1 hour')::int,
                       count(*) filter (where incident_id = @i)::int
                from actions where kind = @k and auto_rule is not null and (@x::uuid is null or id <> @x)
                """;
            cmd.With("k", kind).With("i", incidentId).With("x", exclude);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            await r.ReadAsync(ct);
            return (r.GetInt32(0), r.GetInt32(1));
        }
    }

    /// <summary>revert_after_minutes on a request: only for kinds the board can undo, and within the policy.json ceiling.</summary>
    private static void CheckRevertRequest(string kind, int? minutes, Policy policy)
    {
        if (minutes is not { } m) return;
        if (!Reversal.IsReversible(kind)) throw new BoardException($"revert_after_minutes: {kind} has no automatic revert");
        var max = (policy.FileCeiling ?? policy).Automation.MaxRevertAfterMinutes;
        if (m < 5 || m > max) throw new BoardException($"revert_after_minutes must be 5–{max} (automation.max_revert_after_minutes)");
    }

    public async Task<ActionRow> RequestAsync(Principal p, ActionRequest req, CancellationToken ct = default)
    {
        p.Require(Roles.Requester);
        if (limiter is not null) await limiter.TakeAsync(p, "action_request", ct);
        if (req.Justification is not { Length: >= 20 and <= 4000 }) throw new BoardException("justification must be 20–4000 characters, citing evidence");
        var (def, prms, incidentId, incident, actionFacts) = await PrepareAsync(req.Kind, req.Params, req.Incident, req.ParentId, p.Handle, ct);
        var policy = await PolicyAsync(ct);
        CheckRevertRequest(def.Kind, req.RevertAfterMinutes, policy);
        var decision = PolicyEngine.Assess(def, prms, incident, policy, await AutomationFactsAsync(def.Kind, incidentId, p.Handle, null, policy, ct), req.RevertAfterMinutes, actionFacts);
        var status = decision.Status;

        // A person told the agent to do this on the board (act_on_instruction): their message is the approval, when
        // every check holds. Otherwise the request is refused outright, never quietly filed as something else.
        Instruction? instruction = null;
        if (req.OnBehalfOf is { } instructedIn && decision.Outcome == Outcome.NeedsApproval)
        {
            if (InstructionRules.CheckPolicy(def.Kind, policy, (await GetPauseAsync(ct)).Paused, decision.ApprovalsRequired) is { } refused)
                throw new BoardException(refused);
            instruction = await LoadInstructionAsync(instructedIn, p, def.Kind, ct);
            if (InstructionRules.CheckMessage(instruction, instructedIn, p, incidentId) is { } why) throw new BoardException(why);
            status = "approved";
        }

        // The action row, its board message and the link between them commit together (issue #4): a crash can't
        // leave an action without its message, or a message without its action.
        var autoRule = instruction is null && status == "approved" ? decision.AutoRule : null;
        var notes = decision.Notes.ToList();
        var sys = await system.GetAsync(ct);
        Guid actionId;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            // Automation caps, enforced under a per-kind lock so concurrent requests can't both slip under them. Over
            // the cap the request falls back to a person, never to rejection.
            if (autoRule is not null && policy.ActiveRules.TryGetValue(def.Kind, out var rule))
            {
                await using (var lk = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('auto:' || @k))", conn, tx).With("k", def.Kind))
                    await lk.ExecuteNonQueryAsync(ct);
                var (hour, onIncident) = await AutoRunCountsAsync(new NpgsqlCommand("", conn, tx), def.Kind, incidentId, null, ct);
                if (hour >= rule.Spec.MaxPerHour || onIncident >= rule.Spec.MaxPerIncident)
                {
                    notes.Add($"automation rule {autoRule} not applied: cap reached while filing ({hour} this hour, max {rule.Spec.MaxPerHour}; {onIncident} on this incident, max {rule.Spec.MaxPerIncident})");
                    autoRule = null;
                    status = "pending_approval";
                }
            }
            var needsApproval = status == "pending_approval";
            var approvalsRequired = needsApproval ? Math.Max(1, policy.ApprovalsFor(def.Kind)) : Math.Max(1, decision.ApprovalsRequired);
            var revertAfter = status == "rejected" ? null : PolicyEngine.RevertAfter(def.Kind, policy, autoRule, req.RevertAfterMinutes);
            var label = instruction is not null ? $"approved on @{instruction.AuthorHandle}'s instruction" : status switch
            {
                "rejected" => "REJECTED by policy",
                "approved" when autoRule is not null => $"AUTO-EXECUTED under automation rule {autoRule}",
                "approved" => "auto-approved (non-destructive)",
                _ => approvalsRequired == 2 ? "awaiting two human approvals" : "awaiting human approval",
            };
            var body = $"@{p.Handle} requests **{def.Title}**: {def.Describe(prms)}\n\n> {req.Justification.Replace("\n", "\n> ")}\n\nStatus: **{label}**"
                       + (revertAfter is { } ra ? $"\n\nIt will be undone automatically {ra} minutes after it runs, unless an approver chooses Keep." : "")
                       + (notes.Count > 0 ? "\n\nPolicy notes:\n" + string.Join("\n", notes.Select(n => $"- {n}")) : "");
            if (status == "pending_approval" && incidentId is { } capped) await EnforcePendingCapAsync(conn, tx, p, capped, incident?.GraphId ?? capped.ToString(), ct, policy);
            var note = instruction is null ? null : $"instructed in message {instruction.MessageId}";
            await using (var ins = new NpgsqlCommand("""
                insert into actions (kind, params, incident_id, requested_by, justification, status, requires_approval, policy_notes, expires_at, approvals_required,
                                     on_behalf_of, decided_by, decided_at, decision_note, auto_rule, revert_after_minutes)
                values (@k, @p, @i, @r, @j, @s, @ra, @n, case when @ra then now() + make_interval(secs => @exp) end, @ar,
                        @obo, @db, case when @db::uuid is not null then now() end, @dn, @rule, @rev) returning id
                """, conn, tx).With("k", def.Kind).WithJson("p", prms).With("i", incidentId).With("r", p.Id).With("j", req.Justification)
                .With("s", status).With("ra", needsApproval).With("n", notes.ToArray())
                .With("exp", decision.ExpiresInHours * 3600).With("ar", approvalsRequired)
                .With("obo", instruction?.MessageId).With("db", instruction?.AuthorId).With("dn", note).With("rule", autoRule).With("rev", revertAfter))
            {
                try { actionId = (Guid)(await ins.ExecuteScalarAsync(ct))!; }
                catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation && ex.ConstraintName == "actions_on_behalf_of_kind")
                {
                    throw new BoardException($"on_behalf_of refused: message {instruction!.MessageId} was already used for a request of this kind");
                }
            }
            if (instruction is not null)
                await using (var ap = new NpgsqlCommand("insert into action_approvals (action_id, approver_id, note) values (@id, @p, @n)", conn, tx)
                                 .With("id", actionId).With("p", instruction.AuthorId).With("n", note))
                    await ap.ExecuteNonQueryAsync(ct);
            var msgId = await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment", body, "action_request",
                Json.Element(new { action_id = actionId, kind = def.Kind, @params = prms, status, policy_notes = notes, on_behalf_of = instruction?.MessageId, auto_rule = autoRule }), null, incidentId?.ToString()), system: true, ct);
            await using (var up = new NpgsqlCommand("update actions set request_message_id = @m where id = @id", conn, tx).With("m", msgId).With("id", actionId))
                await up.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(p.Id, "action.requested", actionId.ToString(), new { kind = def.Kind, @params = prms, outcome = status == "pending_approval" ? nameof(Outcome.NeedsApproval) : decision.Outcome.ToString(), notes, on_behalf_of = req.OnBehalfOf, auto_rule = autoRule, revert_after_minutes = req.RevertAfterMinutes }, ct);
        if (autoRule is not null)
            await audit.WriteAsync(null, "action.auto_approved", actionId.ToString(), new { kind = def.Kind, rule = autoRule, requested_by = p.Handle }, ct);
        if (instruction is not null)
            await audit.WriteAsync(instruction.AuthorId, "action.approved", actionId.ToString(),
                new { via = "instruction", message_id = instruction.MessageId, requested_by = p.Handle, approvals = 1, approvals_required = 1 }, ct);

        if (status == "approved") await ExecuteAsync(actionId, ct);
        return (await GetAsync(actionId, ct))!;
    }

    /// <summary>The cited instruction message and its author, with the checks that need the database (age, thread, reuse).</summary>
    private async Task<Instruction?> LoadInstructionAsync(Guid messageId, Principal requester, string kind, CancellationToken ct)
    {
        await using var cmd = db.Command("""
            select m.id, a.id, a.handle, a.kind, a.enabled, a.roles, m.incident_id,
                   extract(epoch from now() - m.created_at)::float8,
                   @h = any(m.mentions),
                   exists (select 1 from messages t where t.author_id = @r and (t.id = coalesce(m.parent_id, m.id) or t.parent_id = coalesce(m.parent_id, m.id))),
                   exists (select 1 from actions x where x.on_behalf_of = m.id and x.kind = @k)
            from messages m join principals a on a.id = m.author_id
            where m.id = @id
            """).With("id", messageId).With("h", requester.Handle).With("r", requester.Id).With("k", kind);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return null;
        return new Instruction(r.GetGuid(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetBoolean(4), r.GetFieldValue<string[]>(5),
            r.IsDBNull(6) ? null : r.GetGuid(6), TimeSpan.FromSeconds(r.GetDouble(7)), r.GetBoolean(8), r.GetBoolean(9), r.GetBoolean(10));
    }

    /// <summary>Indicators marked malicious in ioc messages on an incident, as normalised "kind:value".</summary>
    private async Task<HashSet<string>> MaliciousIocsAsync(Guid incidentId, string excludeAuthor, CancellationToken ct)
    {
        var set = new HashSet<string>();
        await using var cmd = db.Command("""
            select i->>'kind', i->>'value' from messages m join principals a on a.id = m.author_id, jsonb_array_elements(m.payload->'indicators') i
            where m.incident_id = @i and m.type = 'ioc' and i->>'verdict' = 'malicious' and a.handle <> @x
            """).With("i", incidentId).With("x", excludeAuthor);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            if (Intel.Indicators.Normalise(r.GetString(0), r.GetString(1)) is { } v) set.Add($"{r.GetString(0)}:{v}");
        return set;
    }

    /// <summary>
    /// Too many requests already waiting on one incident (issue #5), so a looping agent can't flood the approval queue.
    /// Locks the incident row so concurrent requests count correctly.
    /// </summary>
    private async Task EnforcePendingCapAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Principal p, Guid incidentId, string graphId, CancellationToken ct, Policy policy)
    {
        // FOR NO KEY UPDATE, not FOR UPDATE: it still queues concurrent requesters on this incident, but doesn't block
        // the KEY SHARE a message insert takes on the incident while holding the feed lock (that ordering deadlocked).
        await using (var lk = new NpgsqlCommand("select 1 from incidents where id = @i for no key update", conn, tx).With("i", incidentId))
            await lk.ExecuteNonQueryAsync(ct);
        await using var cnt = new NpgsqlCommand("select count(*)::int from actions where incident_id = @i and status = any(@open)", conn, tx)
            .With("i", incidentId).With("open", ActionStatus.Open);
        var open = (int)(await cnt.ExecuteScalarAsync(ct))!;
        var cap = policy.Limits.PendingActionsPerIncident;
        if (open < cap) return;
        // Audited on this transaction's connection (no second pooled connection while the incident row is locked),
        // and committed even though the request itself is refused.
        await using (var au = new NpgsqlCommand("insert into audit_log (actor_id, event, subject, detail) values (@a, 'limit.hit', @s, @d)", conn, tx)
                         .With("a", p.Id).With("s", p.Handle).WithJson("d", new { bucket = "pending_actions_per_incident", incident = graphId, limit = cap }))
            await au.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
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
        var policy = await PolicyAsync(ct);
        var required = Math.Max(a.ApprovalsRequired, policy.ApprovalsFor(a.Kind));
        if (decision == "approve")
        {
            if (a.Approvals?.Contains(p.Handle) == true) throw BoardException.Conflict("you already approved this action; a different approver must complete it");
            var incident = a.IncidentId is { } iid ? await LoadIncidentAsync(iid, a.RequestedBy, ct) : null;
            var actionFacts = await ActionFactsForAsync(a, ct);
            if (policy.ConfirmsTarget(a.Kind))
            {
                var names = ConfirmNames(a, incident, actionFacts);
                if (confirm is null || !names.Contains(confirm.Trim(), StringComparer.OrdinalIgnoreCase))
                    throw new BoardException($"type the target ({names.FirstOrDefault()}) to confirm this approval");
            }
            // The situation may have changed since the request (policy reloaded, evidence updated): re-run policy now.
            var now = PolicyEngine.Assess(def, def.Validate(a.Params), incident, policy, actionFacts: actionFacts);
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
                update actions set status = 'rejected', held_at = null, policy_notes = array_append(policy_notes, @why), updated_at = now()
                where id = @id and (status = any(@open) or (status = 'approved' and held_at is not null) or status = 'running')
                """, conn, tx).With("why", $"rejected when re-checked: {reason}").With("id", a.Id).With("open", ActionStatus.Open))
                if (await up.ExecuteNonQueryAsync(ct) == 0) return;
            await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment",
                $"**{Catalog.Get(a.Kind).Title}** is now **rejected by policy**: {reason}. @{a.RequestedBy}'s request was re-checked before running (triggered by @{p.Handle}).",
                "status", Json.Element(new { state = "action_rejected", action_id = a.Id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(p.Id, "action.rejected_on_recheck", a.Id.ToString(), new { reason }, ct);
    }

    /// <summary>Expire one open or held action whose time is up: status, a reply in its thread that @mentions the requester, an audit row.</summary>
    private async Task<bool> ExpireOneAsync(Guid id, CancellationToken ct)
    {
        var sys = await system.GetAsync(ct);
        // Read before the transaction: borrowing a second pooled connection while one is held can exhaust the pool.
        if (await GetAsync(id, ct) is not { } a) return false;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using (var up = new NpgsqlCommand("""
                update actions set status = 'expired', held_at = null, updated_at = now()
                where id = @id and (status = any(@open) or (status = 'approved' and held_at is not null)) and expires_at <= now() returning id
                """, conn, tx).With("id", id).With("open", ActionStatus.Open))
                if (await up.ExecuteScalarAsync(ct) is null) return false;
            await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment",
                $"**{Catalog.Get(a.Kind).Title}** **expired** without {(a.Approvals is { Length: > 0 } ? "a second approval" : "a decision")}. @{a.RequestedBy} can request it again if it's still needed.",
                "status", Json.Element(new { state = "action_expired", action_id = id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(null, "action.expired", id.ToString(), new { kind = a.Kind, expires_at = a.ExpiresAt, approvals = a.Approvals }, ct);
        return true;
    }

    /// <summary>Expiry sweep, run by the recovery timer: open and held actions past expires_at become expired.</summary>
    public async Task<int> ExpireDueAsync(CancellationToken ct = default)
    {
        var due = new List<Guid>();
        await using (var cmd = db.Command("select id from actions where (status = any(@open) or (status = 'approved' and held_at is not null)) and expires_at <= now() order by expires_at limit 100").With("open", ActionStatus.Open))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) due.Add(r.GetGuid(0));
        var n = 0;
        foreach (var id in due) if (await ExpireOneAsync(id, ct)) n++;
        return n;
    }


    public async Task<BrokerPause> GetPauseAsync(CancellationToken ct = default) =>
        await _kv.GetAsync<BrokerPause>(KvState.BrokerPaused, ct) ?? new BrokerPause(false);

    /// <summary>Admin pause switch. Read from the database on every execute, so it holds on every instance at once.</summary>
    public async Task<BrokerPause> SetPauseAsync(Principal p, bool paused, string? reason, CancellationToken ct = default)
    {
        p.Require(Roles.Admin);
        if (!p.IsHuman) throw BoardException.Forbidden("only people can pause or resume the broker");
        reason = reason?.Trim();
        if (reason is not { Length: >= 5 and <= 500 }) throw new BoardException("reason must be 5–500 characters");
        var state = new BrokerPause(paused, p.Handle, DateTimeOffset.UtcNow, reason);
        await _kv.SetAsync(KvState.BrokerPaused, state, ct);
        await audit.WriteAsync(p.Id, paused ? "broker.paused" : "broker.resumed", null, new { reason }, ct);
        await board.PostAsync(await system.GetAsync(ct), new PostInput("general", paused
            ? $"@{p.Handle} **paused the broker**: no action runs until an admin resumes it. Approvals are still recorded. Reason: {reason}"
            : $"@{p.Handle} **resumed the broker**. Actions approved during the pause wait for an approver to choose Run now. Reason: {reason}",
            "status", Json.Element(new { state = paused ? "broker_paused" : "broker_resumed" })), system: true, ct);
        return state;
    }

    /// <summary>Pure policy guard checked at execution time so delayed, held or recovered actions cannot bypass new protections.</summary>
    internal static PolicyDecision GuardExecutionPolicy(ActionDef def, JsonObject prms, IncidentContext? incident, Policy policy,
        AutomationFacts? automationFacts = null, ActionFacts? actionFacts = null) =>
        PolicyEngine.Evaluate(def, prms, incident, policy, automationFacts, actionFacts);

    /// <summary>
    /// Run an action that was approved while the broker was paused. Re-checks expiry, typed target confirmation and
    /// current policy before releasing so post-pause policy additions cannot be bypassed.
    /// </summary>
    public async Task<ActionRow> RunNowAsync(Principal p, Guid id, CancellationToken ct = default, string? confirm = null)
    {
        if (!p.IsHuman || !p.Has(Roles.Approver)) throw BoardException.Forbidden("only human approvers can run held actions");
        var pause = await GetPauseAsync(ct);
        if (pause.Paused) throw BoardException.Conflict($"broker paused by @{pause.By}");
        var a = await GetAsync(id, ct) ?? throw BoardException.NotFound("action");
        if (a.RequestedBy == p.Handle) throw BoardException.Forbidden("you cannot run your own request");
        var policy = await PolicyAsync(ct);
        if (a.Status != "approved" || a.HeldAt is null) throw BoardException.Conflict(a.Status == "approved" ? "action is not held" : $"action is {a.Status}");
        if (a.ExpiresAt is { } exp && exp <= DateTimeOffset.UtcNow)
        {
            await ExpireOneAsync(id, ct);
            throw BoardException.Conflict("action is expired");
        }

        var def = Catalog.Get(a.Kind);
        var incident = a.IncidentId is { } iid ? await LoadIncidentAsync(iid, a.RequestedBy, ct) : null;
        var actionFacts = await ActionFactsForAsync(a, ct);
        if (policy.ConfirmsTarget(a.Kind))
        {
            var names = ConfirmNames(a, incident, actionFacts);
            if (confirm is null || !names.Contains(confirm.Trim(), StringComparer.OrdinalIgnoreCase))
                throw new BoardException($"type the target ({names.FirstOrDefault()}) to confirm running this held action");
        }
        var now = PolicyEngine.Assess(def, def.Validate(a.Params), incident, policy, actionFacts: actionFacts);
        if (now.Outcome == Outcome.Reject)
        {
            await RejectOnRecheckAsync(p, a, now.Notes[0], ct);
            throw BoardException.Conflict($"policy now rejects this action: {now.Notes[0]}");
        }

        await using (var cmd = db.Command("update actions set held_at = null, updated_at = now() where id = @id and status = 'approved' and held_at is not null and requested_by <> @p and (expires_at is null or expires_at > now()) returning id").With("id", id).With("p", p.Id))
            if (await cmd.ExecuteScalarAsync(ct) is null)
            {
                var latest = (await GetAsync(id, ct))!;
                if (latest.ExpiresAt is { } lexp && lexp <= DateTimeOffset.UtcNow) { await ExpireOneAsync(id, ct); throw BoardException.Conflict("action is expired"); }
                throw BoardException.Conflict(latest.Status == "approved" ? "action is not held" : $"action is {latest.Status}");
            }
        await audit.WriteAsync(p.Id, "action.released", id.ToString(), null, ct);
        await ExecuteAsync(id, ct);
        return (await GetAsync(id, ct))!;
    }

    /// <summary>
    /// Run an approved action exactly once (claimed by the approved → running transition). The pause switch is part
    /// of the claim, so a pause set on any instance stops the next execution everywhere; the action is held instead.
    /// </summary>
    public async Task ExecuteAsync(Guid id, CancellationToken ct = default)
    {
        await using (var claim = db.Command($"""
            update actions set status = 'running', started_at = now(), updated_at = now()
            where id = @id and status = 'approved' and held_at is null
              and not exists (select 1 from kv_state where key = '{KvState.BrokerPaused}' and (value ->> 'paused')::boolean)
            returning id
            """).With("id", id))
            if (await claim.ExecuteScalarAsync(ct) is null)
            {
                await HoldIfPausedAsync(id, ct);
                return;
            }
        var a = (await GetAsync(id, ct))!;
        var def = Catalog.Get(a.Kind);
        var incident = a.IncidentId is { } iid ? await LoadIncidentAsync(iid, a.RequestedBy, ct) : null;
        var approvers = a.Approvals is { Length: > 0 } list ? string.Join(" and ", list) : a.DecidedBy;
        var comment = $"blueboard action {id} for incident {a.IncidentGraphId ?? "n/a"}, requested by {a.RequestedBy}"
                      + (approvers is null ? a.AutoRule is { } ar ? $" (auto-executed under rule {ar})" : " (auto-approved)" : $", approved by {approvers}") + $": {a.Justification}";
        string status;
        object? result = null;
        string? error = null;
        JsonObject? prms = null;
        JsonObject? prepared = null;
        try
        {
            prms = def.Validate(a.Params); // never run a write from unchecked stored JSON
            var policy = await PolicyAsync(ct);
            var automationFacts = a.AutoRule is null ? null : await AutomationFactsAsync(a.Kind, a.IncidentId, a.RequestedBy, a.Id, policy, ct);
            var actionFacts = await ActionFactsAsync(def, prms, a.CreatedAt, ct);
            var recheck = GuardExecutionPolicy(def, prms, incident, policy, automationFacts, actionFacts);
            if (recheck.Outcome == Outcome.Reject)
            {
                await RejectOnRecheckAsync(await system.GetAsync(ct), a, recheck.Notes[0], ct);
                return;
            }
            // Ran without a person under a rule: the rule must still hold now (paused, tightened, a dissenting verdict).
            if (a.AutoRule is not null && a.DecidedBy is null && recheck.AutoRule is null)
            {
                await ReturnToApprovalAsync(a, recheck.Notes.LastOrDefault() ?? "automation no longer applies", policy, ct);
                return;
            }
            prepared = def.Prepare?.Invoke(prms, new ActionContext(id, a.IncidentGraphId, a.IncidentId, a.RequestedBy, a.DecidedBy, a.Justification, settings.Ti, DateTimeOffset.UtcNow, actionFacts?.Data));
            result = !settings.BrokerExecute
                ? new { dry_run = true, would = def.Describe(prms), request = prepared }
                : def.RunConnector is { } runConnector
                    ? await runConnector(connectors ?? throw new BoardException($"{def.Kind} needs a connector that is not configured on this board"), prms, comment, ct)
                    : await def.Run(ms, prepared ?? prms, comment, ct);
            status = "succeeded";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            status = "failed";
            error = ex.Message;
        }
        // A successful action with revert_after_minutes is scheduled to be undone; the timer files the reverse action.
        var revertAt = status == "succeeded" && a.RevertAfterMinutes is { } mins && Reversal.IsReversible(a.Kind) && a.RevertOf is null
            ? DateTimeOffset.UtcNow.AddMinutes(mins) : (DateTimeOffset?)null;
        await using (var up = db.Command("""
            update actions set status = @s, result = @r, error = @e, finished_at = now(), updated_at = now(),
                   revert_at = coalesce(@ra, revert_at), revert_state = case when @ra::timestamptz is not null then 'scheduled' else revert_state end
            where id = @id
            """).With("s", status).WithJson("r", result).With("e", error).With("ra", revertAt).With("id", id))
            await up.ExecuteNonQueryAsync(ct);
        await audit.WriteAsync(null, $"action.{status}", id.ToString(), new { error, auto_rule = a.AutoRule, revert_at = revertAt, revert_of = a.RevertOf }, ct);
        var text = status == "succeeded"
            ? $"**{def.Title}** {(settings.BrokerExecute ? "completed" : "completed (dry run: BROKER_EXECUTE is off)")}{(a.AutoRule is { } rule ? $", auto-executed under rule {rule}" : "")}: {def.Describe(prms!)}"
              + ResultDetail(settings.BrokerExecute, prepared, result)
              + (revertAt is { } at ? $"\n\n@{a.RequestedBy} it will be undone automatically at {at:yyyy-MM-dd HH:mm} UTC. An approver can choose **Keep** or **Revert now** on Approvals." : "")
            : $"**{def.Title}** failed: {error}";
        await board.PostAsync(await system.GetAsync(ct), new PostInput("containment", text, "action_result",
            Json.Element(new { action_id = id, status, error, auto_rule = a.AutoRule, revert_at = revertAt, revert_of = a.RevertOf }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
        if (a.RevertOf is { } original) await SettleRevertAsync(original, id, status == "succeeded" ? "reverted" : "failed", error, ct);
        // Overturn tracking: an incident really resolved here is compared with the latest agent verdict on it.
        if (status == "succeeded" && settings.BrokerExecute && feedback is not null && def.Kind == "update_incident"
            && prms?["status"]?.GetValue<string>() == "resolved" && prms["classification"]?.GetValue<string>() is { } resolvedAs)
        {
            var incidentId = a.IncidentId ?? await board.ResolveIncidentAsync(prms["incident_id"]?.GetValue<string>(), ct);
            if (incidentId is { } resolvedIncident) await feedback.RecordResolutionAsync(resolvedIncident, resolvedAs, "update_incident", ct);
        }
    }

    /// <summary>
    /// An auto-approved action whose rule no longer holds at execution (automation paused, the rule tightened, a
    /// verdict now disagrees): it goes back to the approval queue instead of running.
    /// </summary>
    private async Task ReturnToApprovalAsync(ActionRow a, string why, Policy policy, CancellationToken ct)
    {
        var sys = await system.GetAsync(ct);
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using (var up = new NpgsqlCommand("""
                update actions set status = 'pending_approval', requires_approval = true, auto_rule = null, started_at = null,
                       expires_at = now() + make_interval(secs => @exp), approvals_required = @ar,
                       policy_notes = array_append(policy_notes, @why), updated_at = now()
                where id = @id and status = 'running'
                """, conn, tx).With("exp", policy.ExpiryFor(a.Kind).TotalSeconds).With("ar", Math.Max(1, policy.ApprovalsFor(a.Kind)))
                .With("why", $"re-checked before running: {why}").With("id", a.Id))
                if (await up.ExecuteNonQueryAsync(ct) == 0) return;
            await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment",
                $"**{Catalog.Get(a.Kind).Title}** did not run automatically: {why}. It now waits for a human approver (requested by @{a.RequestedBy}).",
                "status", Json.Element(new { state = "action_pending_approval", action_id = a.Id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(null, "action.auto_withdrawn", a.Id.ToString(), new { rule = a.AutoRule, reason = why }, ct);
    }

    // ── automatic revert ───────────────────────────────────────────────────────────────────────

    /// <summary>Timer sweep: file the reverse action for every action whose revert is due.</summary>
    public async Task<int> RevertDueAsync(CancellationToken ct = default)
    {
        // A revert action that ended without running (denied, expired, rejected on re-check) leaves the original in
        // place: mark it failed so a person hears about it, instead of leaving it "reverting" for ever.
        var stuck = new List<(Guid Id, Guid Revert, string Status)>();
        await using (var cmd = db.Command("""
            select o.id, r.id, r.status from actions o join actions r on r.id = o.revert_action_id
            where o.revert_state = 'reverting' and r.status in ('denied', 'expired', 'rejected') limit 20
            """))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) stuck.Add((r.GetGuid(0), r.GetGuid(1), r.GetString(2)));
        foreach (var (id, rev, st) in stuck) await SettleRevertAsync(id, rev, "failed", $"the revert action was {st}", ct);

        var due = new List<Guid>();
        await using (var cmd = db.Command("select id from actions where revert_state = 'scheduled' and revert_at <= now() order by revert_at limit 20"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) due.Add(r.GetGuid(0));
        var n = 0;
        foreach (var id in due)
            if (await RevertAsync(id, null, null, ct)) n++;
        return n;
    }

    /// <summary>
    /// Keep (cancel the scheduled revert) or Revert now. Human approvers only, never over MCP; an agent can't stop or
    /// trigger a revert. Revert now runs the reverse action as approved by that person.
    /// </summary>
    public async Task<ActionRow> RevertOpAsync(Principal p, Guid id, RevertOpInput input, CancellationToken ct = default)
    {
        if (!p.IsHuman || !p.Has(Roles.Approver)) throw BoardException.Forbidden("only human approvers can keep or revert actions");
        var a = await GetAsync(id, ct) ?? throw BoardException.NotFound("action");
        if (!Reversal.IsReversible(a.Kind)) throw new BoardException($"{a.Kind} has no automatic revert");
        if (input.Op == "keep")
        {
            if (a.RevertState != "scheduled") throw BoardException.Conflict(a.RevertState is null ? "no revert is scheduled" : $"revert is {a.RevertState}");
            await using (var up = db.Command("update actions set revert_state = 'kept', updated_at = now() where id = @id and revert_state = 'scheduled' returning id").With("id", id))
                if (await up.ExecuteScalarAsync(ct) is null) throw BoardException.Conflict("revert is no longer scheduled");
            await audit.WriteAsync(p.Id, "action.revert_kept", id.ToString(), new { note = input.Note, revert_at = a.RevertAt }, ct);
            await board.PostAsync(await system.GetAsync(ct), new PostInput("containment",
                $"@{p.Handle} chose **Keep**: {Catalog.Get(a.Kind).Title} stays in place and won't be undone automatically (requested by @{a.RequestedBy}).{(input.Note is { Length: > 0 } n ? $" Note: {n}" : "")}",
                "status", Json.Element(new { state = "revert_kept", action_id = id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
        }
        else
        {
            if (a.Status != "succeeded") throw BoardException.Conflict($"action is {a.Status}; only a completed action can be reverted");
            if (a.RevertState is not (null or "scheduled" or "kept" or "failed")) throw BoardException.Conflict($"revert is {a.RevertState}");
            if (!await RevertAsync(id, p, input.Note, ct)) throw BoardException.Conflict("a revert for this action was already filed");
        }
        return (await GetAsync(id, ct))!;
    }

    /// <summary>
    /// File (and normally run) the reverse action as the board's system principal. Policy is re-checked: a rejection
    /// (say the device became protected) marks the revert failed and tells the requester. While automation is paused, a
    /// timer revert waits for a person like any other request. Exactly once per action (unique index on revert_of).
    /// </summary>
    private async Task<bool> RevertAsync(Guid id, Principal? by, string? note, CancellationToken ct)
    {
        await using (var claim = db.Command("""
            update actions set revert_state = 'reverting', updated_at = now()
            where id = @id and status = 'succeeded' and revert_action_id is null
              and (revert_state = 'scheduled' or (@human and revert_state in ('kept', 'failed')) or (@human and revert_state is null))
            returning id
            """).With("id", id).With("human", by is not null))
            if (await claim.ExecuteScalarAsync(ct) is null) return false;
        var a = (await GetAsync(id, ct))!;
        var sys = await system.GetAsync(ct);
        var (kind, prms, why) = Reversal.Build(a.Kind, Catalog.Get(a.Kind).Validate(a.Params), a.Result, a.Id);
        if (kind is null)
        {
            await SettleRevertAsync(id, null, "failed", why, ct);
            return true;
        }
        var def = Catalog.Get(kind);
        var policy = await PolicyAsync(ct);
        var incident = a.IncidentId is { } iid ? await LoadIncidentAsync(iid, sys.Handle, ct) : null;
        var decision = PolicyEngine.Evaluate(def, prms!, incident, policy, actionFacts: await ActionFactsAsync(def, prms!, DateTimeOffset.UtcNow, ct));
        if (decision.Outcome == Outcome.Reject)
        {
            await SettleRevertAsync(id, null, "failed", $"policy rejects {kind}: {decision.Notes[0]}", ct);
            return true;
        }
        var paused = by is null && (await PauseOfAutomationAsync(ct)).Paused;
        var status = paused ? "pending_approval" : "approved";
        var justification = by is null
            ? $"Automatic revert of action {id} ({a.Kind}) {a.RevertAfterMinutes} minutes after it ran, as scheduled{(a.AutoRule is { } r ? $" by automation rule {r}" : "")}."
            : $"Revert now of action {id} ({a.Kind}), chosen by @{by.Handle}{(note is { Length: > 0 } n ? $": {n}" : ".")}";
        Guid revertId;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using (var ins = new NpgsqlCommand("""
                insert into actions (kind, params, incident_id, requested_by, justification, status, requires_approval, policy_notes, expires_at, approvals_required,
                                     decided_by, decided_at, decision_note, revert_of)
                values (@k, @p, @i, @r, @j, @s, @ra, @n, case when @ra then now() + make_interval(secs => @exp) end, 1,
                        @db, case when @db::uuid is not null then now() end, @dn, @of) returning id
                """, conn, tx).With("k", kind).WithJson("p", prms).With("i", a.IncidentId).With("r", sys.Id).With("j", justification)
                .With("s", status).With("ra", paused).With("n", decision.Notes.Append(paused ? "automation is paused, so this revert waits for a person" : $"automatic revert of action {id}").ToArray())
                .With("exp", policy.ExpiryFor(kind).TotalSeconds).With("db", by?.Id).With("dn", by is null ? null : "revert now").With("of", id))
            {
                try { revertId = (Guid)(await ins.ExecuteScalarAsync(ct))!; }
                catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation && ex.ConstraintName == "actions_one_revert")
                {
                    await tx.RollbackAsync(ct);
                    return false;
                }
            }
            if (by is not null)
                await using (var ap = new NpgsqlCommand("insert into action_approvals (action_id, approver_id, note) values (@id, @p, 'revert now')", conn, tx).With("id", revertId).With("p", by.Id))
                    await ap.ExecuteNonQueryAsync(ct);
            await using (var link = new NpgsqlCommand("update actions set revert_action_id = @r, updated_at = now() where id = @id", conn, tx).With("r", revertId).With("id", id))
                await link.ExecuteNonQueryAsync(ct);
            // Posted in the original action's thread; the revert's later status and result replies go there too.
            var msg = await board.PostInTransactionAsync(conn, tx, sys, new PostInput("containment",
                $"@{a.RequestedBy} {(by is null ? "**Automatic revert**" : $"@{by.Handle} chose **Revert now**")}: {def.Title}: {def.Describe(prms!)}. Status: **{(paused ? "awaiting human approval (automation paused)" : "approved, running")}**",
                "action_request", Json.Element(new { action_id = revertId, kind, @params = prms, status, revert_of = id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
            await using (var up = new NpgsqlCommand("update actions set request_message_id = coalesce(@root, @m) where id = @id", conn, tx)
                             .With("root", a.RequestMessageId).With("m", msg).With("id", revertId))
                await up.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
        }
        await audit.WriteAsync(by?.Id, "action.revert_filed", revertId.ToString(), new { revert_of = id, kind, via = by is null ? "timer" : "revert_now", paused }, ct);
        if (!paused) await ExecuteAsync(revertId, ct);
        return true;
    }

    private async Task<AutomationPause> PauseOfAutomationAsync(CancellationToken ct) =>
        store is null ? (await PolicyAsync(ct)).Pause ?? new AutomationPause(false) : await store.PauseAsync(ct);

    /// <summary>Record how a revert ended on the original action; a failure is posted with an @mention and audited.</summary>
    private async Task SettleRevertAsync(Guid original, Guid? revertId, string state, string? why, CancellationToken ct)
    {
        await using (var up = db.Command("update actions set revert_state = @s, updated_at = now() where id = @id and revert_state is distinct from @s returning id")
                         .With("s", state).With("id", original))
            if (await up.ExecuteScalarAsync(ct) is null) return;
        await audit.WriteAsync(null, state == "reverted" ? "action.reverted" : "action.revert_failed", original.ToString(), new { revert_action_id = revertId, reason = why }, ct);
        if (state != "failed" || await GetAsync(original, ct) is not { } a) return;
        await board.PostAsync(await system.GetAsync(ct), new PostInput("containment",
            $"@{a.RequestedBy} **automatic revert failed** for {Catalog.Get(a.Kind).Title}: {why ?? "see the revert action"}. It is still in place: check Defender/Entra and undo it by hand if needed.",
            "status", Json.Element(new { state = "revert_failed", action_id = original, revert_action_id = revertId }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
    }

    private async Task HoldIfPausedAsync(Guid id, CancellationToken ct)
    {
        var pause = await GetPauseAsync(ct);
        if (!pause.Paused) return;
        await using (var hold = db.Command("update actions set held_at = now(), updated_at = now() where id = @id and status = 'approved' and held_at is null returning id").With("id", id))
            if (await hold.ExecuteScalarAsync(ct) is null) return;
        var a = (await GetAsync(id, ct))!;
        await audit.WriteAsync(null, "action.held", id.ToString(), new { paused_by = pause.By }, ct);
        await board.PostAsync(await system.GetAsync(ct), new PostInput("containment",
            $"**{Catalog.Get(a.Kind).Title}** is approved but **held**: broker paused by @{pause.By}. Once the broker is resumed, an approver can choose Run now on the Approvals page.",
            "status", Json.Element(new { state = "action_held", action_id = id }), a.RequestMessageId, a.IncidentId?.ToString()), system: true, ct);
    }

    /// <summary>Dry run: the exact request that would be sent. Live: the result fields (for example the STIX id and where to find it).</summary>
    private static string ResultDetail(bool executed, JsonObject? prepared, object? result)
    {
        var indented = new JsonSerializerOptions { WriteIndented = true };
        if (!executed && prepared is not null)
            return $"\n\nExact request that would be sent:\n\n```\n{prepared.ToJsonString(indented)}\n```";
        if (executed && prepared is not null && result is not null)
            return $"\n\n```\n{JsonSerializer.Serialize(result, indented)}\n```";
        return "";
    }

    /// <summary>
    /// Recovery for actions a crash left behind. approved &gt; 1 min: never started, safe to run.
    /// running &gt; 10 min: may or may not have reached Defender, so never re-run blindly: mark failed and say so.
    /// </summary>
    public async Task<(int Resumed, int Interrupted)> RecoverAsync(CancellationToken ct = default)
    {
        var stuck = new List<Guid>();
        await using (var cmd = db.Command("select id from actions where status = 'approved' and held_at is null and updated_at < now() - interval '1 minute' order by created_at limit 20"))
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
