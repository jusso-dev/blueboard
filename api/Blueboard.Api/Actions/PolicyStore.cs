using System.Text.Json;
using System.Text.RegularExpressions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Npgsql;

namespace Blueboard.Api.Actions;

public sealed record TriggerMatch(string[] Severities, string[] Sources, string[] Titles, string[] Categories, string[] Techniques)
{
    public PlaybookMatch ToPlaybookMatch() => new(Categories, Titles, Techniques, Sources, Severities);
    public static TriggerMatch From(PlaybookMatch m) => new(m.Severities ?? [], m.ServiceSources ?? [], m.Titles, m.Categories, m.Techniques);
}

/// <summary>A playbook auto-attach trigger as stored (policy_changes before/after, playbook_triggers).</summary>
public sealed record TriggerSetting(string PlaybookId, int Priority, TriggerMatch Match, bool Enabled);

/// <summary>One trigger in force. File triggers come from playbooks/*.md (id file-&lt;playbook&gt;); Edited when an admin changed one.</summary>
public sealed record PlaybookTrigger(string Id, string Source, string PlaybookId, int Priority, TriggerMatch Match, bool Enabled, long? Version, bool Edited);

public sealed record PolicyChange(
    Guid Id, string Target, JsonElement? Before, JsonElement? After, bool Loosening, string Reason, string Status,
    string RequestedBy, DateTimeOffset RequestedAt, DateTimeOffset ExpiresAt, string? DecidedBy, DateTimeOffset? DecidedAt, string? DecisionNote);

/// <summary>One action kind on /policy: what policy.json says, the admin override, and the result.</summary>
public sealed record KindView(
    string Kind, string Title, bool Destructive, bool Reversible, string? ReverseKind, bool CeilingAllowsRule,
    KindSetting File, KindSetting? Override, long? OverrideVersion, KindSetting Effective, string? RuleId, string Mode);

public sealed record AutomationView(
    AutomationPolicy Ceiling, AutomationPause Pause, IReadOnlyList<KindView> Kinds, IReadOnlyList<PlaybookTrigger> Triggers,
    IReadOnlyList<PolicyChange> Pending, IReadOnlyList<PolicyChange> History, bool CanEdit);

/// <summary>
/// The admin override store (db/migrations/015). policy.json is the ceiling; overrides only narrow it, and the
/// effective policy is file ∩ overrides (<see cref="AutomationRules.Merge"/>), read from PostgreSQL with a short cache so
/// every Function App instance converges within seconds. Only human Board.Admin principals change it, never over MCP.
/// Tightening applies at once; loosening waits for a second, different admin (enforced here and by SQL checks).
/// Every change is audited.
/// </summary>
public sealed partial class PolicyStore(Db db, Audit audit, BoardService board, SystemPrincipal system, Policy file, PlaybookSet playbooks)
{
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(5);
    public const string PauseKey = "automation_paused";
    private const string FilePrefix = "file-";
    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,63}$")] private static partial Regex TriggerId();
    [GeneratedRegex(@"^T\d{4}(\.\d{3})?$")] private static partial Regex Technique();

    /// <summary>One immutable snapshot, swapped by reference so concurrent readers never see a torn value.</summary>
    private sealed record Snapshot(Policy Policy, IReadOnlyList<PlaybookTrigger> Triggers, DateTimeOffset At);
    private volatile Snapshot? _cache;

    public Policy File => file;

    /// <summary>The effective policy now. Cached for <see cref="CacheFor"/>; a change on this instance invalidates it at once.</summary>
    public async Task<Policy> CurrentAsync(CancellationToken ct = default) => (await LoadAsync(ct)).Policy;

    public void Invalidate() => _cache = null;

    private async Task<Snapshot> LoadAsync(CancellationToken ct)
    {
        if (_cache is { } c && DateTimeOffset.UtcNow - c.At < CacheFor) return c;
        var overrides = await OverridesAsync(ct);
        var pause = await PauseAsync(ct);
        var triggers = await TriggersAsync(ct);
        var loaded = new Snapshot(AutomationRules.Merge(file, overrides, pause), triggers, DateTimeOffset.UtcNow);
        _cache = loaded;
        return loaded;
    }

    private async Task<Dictionary<string, (KindSetting Setting, long Version)>> OverridesAsync(CancellationToken ct)
    {
        var map = new Dictionary<string, (KindSetting, long)>();
        await using var cmd = db.Command("select kind, setting::text, version from policy_overrides");
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            // A row that no longer parses or fits policy.json is ignored (the file wins), never widened.
            if (!Catalog.All.ContainsKey(r.GetString(0))) continue;
            KindSetting? s;
            try { s = JsonSerializer.Deserialize<KindSetting>(r.GetString(1), Json.Options); }
            catch (JsonException) { continue; }
            if (s is not null) map[r.GetString(0)] = (s, r.GetInt64(2));
        }
        return map;
    }

    public async Task<AutomationPause> PauseAsync(CancellationToken ct = default) =>
        await new KvState(db).GetAsync<AutomationPause>(PauseKey, ct) ?? new AutomationPause(false);

    // ── playbook triggers ──────────────────────────────────────────────────────────────────────

    public static string FileTriggerId(string playbookId) => FilePrefix + playbookId;

    /// <summary>File triggers (one per playbook, from its front matter) overlaid by admin edits, plus custom triggers.</summary>
    public async Task<IReadOnlyList<PlaybookTrigger>> TriggersAsync(CancellationToken ct = default)
    {
        var rows = new Dictionary<string, PlaybookTrigger>();
        await using (var cmd = db.Command("select id, playbook_id, source, match::text, priority, enabled, version from playbook_triggers"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
            {
                TriggerMatch? m;
                try { m = JsonSerializer.Deserialize<TriggerMatch>(r.GetString(3), Json.Options); }
                catch (JsonException) { continue; }
                if (m is null) continue;
                rows[r.GetString(0)] = new PlaybookTrigger(r.GetString(0), r.GetString(2), r.GetString(1), r.GetInt32(4), Normalise(m), r.GetBoolean(5), r.GetInt64(6), true);
            }
        var list = new List<PlaybookTrigger>();
        foreach (var pb in playbooks.All)
        {
            var id = FileTriggerId(pb.Id);
            list.Add(rows.Remove(id, out var edited) && edited.Source == "file"
                ? edited with { PlaybookId = pb.Id }
                : new PlaybookTrigger(id, "file", pb.Id, pb.Priority, Normalise(TriggerMatch.From(pb.Match)), true, null, false));
        }
        list.AddRange(rows.Values.Where(t => t.Source == "custom").OrderBy(t => t.Id, StringComparer.Ordinal));
        return list;
    }

    /// <summary>The playbook to attach to a new incident: the highest-priority enabled trigger that matches, or null.</summary>
    public async Task<string?> MatchPlaybookAsync(JsonElement incident, CancellationToken ct = default)
    {
        return Pick((await LoadAsync(ct)).Triggers, playbooks, incident);
    }

    /// <remarks>Intel-scoped playbooks run from a threat intel finding and never attach to an incident, whatever a trigger says.</remarks>
    public static string? Pick(IReadOnlyList<PlaybookTrigger> triggers, PlaybookSet playbooks, JsonElement incident) =>
        triggers.Select((t, i) => (t, i)).Where(x => x.t.Enabled && playbooks.Get(x.t.PlaybookId) is { Scope: Playbooks.IncidentScope })
            .OrderByDescending(x => x.t.Priority).ThenBy(x => x.i)
            .FirstOrDefault(x => Playbooks.Matches(x.t.Match.ToPlaybookMatch(), incident)).t?.PlaybookId;

    private static TriggerMatch Normalise(TriggerMatch m) =>
        new(m.Severities ?? [], m.Sources ?? [], m.Titles ?? [], m.Categories ?? [], m.Techniques ?? []);

    // ── view ───────────────────────────────────────────────────────────────────────────────────

    public async Task<AutomationView> ViewAsync(Principal me, CancellationToken ct = default)
    {
        var (effective, triggers, _) = await LoadAsync(ct);
        var overrides = await OverridesAsync(ct);
        var kinds = Catalog.All.Values.Select(d =>
        {
            overrides.TryGetValue(d.Kind, out var o);
            var eff = AutomationRules.Effective(d.Kind, file, o.Setting);
            var allowsRule = d.Destructive && !Catalog.NeverAuto.Contains(d.Kind) && file.Automation.ConditionalAutoAllowed.Contains(d.Kind)
                             && (Reversal.IsReversible(d.Kind) || file.Automation.IrreversibleAutoAllowed.Contains(d.Kind));
            return new KindView(d.Kind, d.Title, d.Destructive, Reversal.IsReversible(d.Kind), Reversal.ReverseKind.GetValueOrDefault(d.Kind), allowsRule,
                AutomationRules.FileSetting(d.Kind, file), o.Setting, o.Setting is null ? null : o.Version, eff,
                effective.ActiveRules.GetValueOrDefault(d.Kind)?.Id, PolicyReport.DisplayModeOf(d.Kind, effective));
        }).ToList();
        return new AutomationView(file.Automation, await PauseAsync(ct), kinds, triggers,
            await ChangesAsync(pending: true, ct), await ChangesAsync(pending: false, ct), CanAdminister(me));
    }

    private static bool CanAdminister(Principal p) => p.IsHuman && p.Has(Roles.Admin);

    private static void RequireAdmin(Principal p)
    {
        // App-only tokens never carry Board.Admin (TokenValidator), and agents never edit policy, whatever their roles say.
        if (!p.IsHuman) throw BoardException.Forbidden("only people can change policy");
        p.Require(Roles.Admin);
    }

    public async Task<IReadOnlyList<PolicyChange>> ChangesAsync(bool pending, CancellationToken ct = default)
    {
        var list = new List<PolicyChange>();
        await using var cmd = db.Command($"""
            select c.id, c.target, c.before::text, c.after::text, c.loosening, c.reason, c.status, rp.handle, c.requested_at, c.expires_at,
                   dp.handle, c.decided_at, c.decision_note
            from policy_changes c join principals rp on rp.id = c.requested_by left join principals dp on dp.id = c.decided_by
            where {(pending ? "c.status = 'pending' and c.expires_at > now()" : "c.status <> 'pending' or c.expires_at <= now()")}
            order by c.requested_at desc limit 100
            """);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(ReadChange(r));
        return list;
    }

    private static PolicyChange ReadChange(NpgsqlDataReader r) => new(
        r.GetGuid(0), r.GetString(1), r.IsDBNull(2) ? null : JsonDocument.Parse(r.GetString(2)).RootElement.Clone(),
        r.IsDBNull(3) ? null : JsonDocument.Parse(r.GetString(3)).RootElement.Clone(), r.GetBoolean(4), r.GetString(5),
        r.GetString(6) == "pending" && r.GetFieldValue<DateTimeOffset>(9) <= DateTimeOffset.UtcNow ? "expired" : r.GetString(6),
        r.GetString(7), r.GetFieldValue<DateTimeOffset>(8), r.GetFieldValue<DateTimeOffset>(9), r.IsDBNull(10) ? null : r.GetString(10),
        r.IsDBNull(11) ? null : r.GetFieldValue<DateTimeOffset>(11), r.IsDBNull(12) ? null : r.GetString(12));

    // ── requesting changes ─────────────────────────────────────────────────────────────────────

    /// <summary>Change one action kind's override. Applied at once when it tightens; otherwise a pending change for a second admin.</summary>
    public async Task<PolicyChange> ChangeKindAsync(Principal p, string kind, KindOverrideInput input, CancellationToken ct = default)
    {
        RequireAdmin(p);
        if (!Catalog.All.ContainsKey(kind)) throw BoardException.NotFound($"action kind {kind}");
        KindSetting? after = null;
        if (!input.Reset)
        {
            if (input.Mode is null || input.ConfirmTarget is null) throw new BoardException("mode and confirm_target are required (or reset: true)");
            after = new KindSetting(input.Mode, input.ConfirmTarget.Value, input.Rule is { } r ? NormaliseRule(r) : null);
            var problems = AutomationRules.OverrideProblems(kind, after, file);
            if (problems.Count > 0) throw new BoardException("override exceeds policy.json or is inconsistent: " + string.Join("; ", problems));
        }
        return await ChangeAsync(p, $"kind:{kind}", input.Reason, after is null ? null : Json.Element(after), (before, next) =>
        {
            var b = AutomationRules.Effective(kind, file, Parse<KindSetting>(before));
            var a = AutomationRules.Effective(kind, file, Parse<KindSetting>(next));
            return AutomationRules.IsLooser(b, a);
        }, ct);
    }

    private static AutoRuleSpec NormaliseRule(AutoRuleSpec r) => r with
    {
        Severities = r.Severities?.Select(s => s.Trim().ToLowerInvariant()).Distinct().Order(StringComparer.Ordinal).ToArray(),
        Sources = r.Sources is { Length: > 0 } s ? s.Select(x => x.Trim()).Distinct().ToArray() : null,
        Requesters = r.Requesters is { Length: > 0 } q ? q.Select(x => x.Trim().TrimStart('@').ToLowerInvariant()).Distinct().ToArray() : null,
    };

    /// <summary>Add, edit, disable or remove a playbook trigger. Disabling or removing applies at once; anything else needs a second admin.</summary>
    public async Task<PolicyChange> ChangeTriggerAsync(Principal p, string id, TriggerInput input, CancellationToken ct = default)
    {
        RequireAdmin(p);
        if (!TriggerId().IsMatch(id)) throw new BoardException("trigger id must be a lower-case slug (a-z, 0-9, -)");
        var isFile = id.StartsWith(FilePrefix, StringComparison.Ordinal);
        var filePb = isFile ? playbooks.Get(id[FilePrefix.Length..]) : null;
        if (isFile && filePb is null) throw new BoardException($"{id}: no playbook file {id[FilePrefix.Length..]}; custom trigger ids can't start with {FilePrefix}");
        TriggerSetting? after = null;
        if (input.Remove)
        {
            if (isFile) throw new BoardException("a playbook file's trigger can't be removed; disable it instead");
        }
        else
        {
            var pbId = isFile ? filePb!.Id : input.PlaybookId ?? throw new BoardException("playbook_id is required");
            if (isFile && input.PlaybookId is { } other && other != pbId) throw new BoardException($"{id} always attaches {pbId}");
            if (playbooks.Get(pbId) is not { } target) throw BoardException.NotFound($"playbook '{pbId}'");
            if (target.Scope != Playbooks.IncidentScope && input.Enabled)
                throw new BoardException($"playbook '{pbId}' has scope {target.Scope}: it runs from a threat intel finding and can't be attached to incidents by a trigger");
            var m = new TriggerMatch(Clean(input.Severities), Clean(input.Sources), Clean(input.Titles), Clean(input.Categories), Clean(input.Techniques));
            if (m.Sources.Length + m.Titles.Length + m.Categories.Length + m.Techniques.Length == 0)
                throw new BoardException("a trigger needs at least one of sources, titles, categories or techniques");
            if (m.Severities.FirstOrDefault(s => !AutomationRules.Severities.Contains(s.ToLowerInvariant())) is { } bad)
                throw new BoardException($"unknown severity {bad}");
            if (m.Techniques.FirstOrDefault(t => !Technique().IsMatch(t)) is { } badT) throw new BoardException($"invalid MITRE technique '{badT}' (use T1234 or T1234.001)");
            after = new TriggerSetting(pbId, input.Priority, m, input.Enabled);
        }
        return await ChangeAsync(p, $"trigger:{id}", input.Reason, after is null ? null : Json.Element(after),
            (_, next) => Parse<TriggerSetting>(next) is { Enabled: true }, ct);

        static string[] Clean(string[]? xs)
        {
            var list = (xs ?? []).Select(x => x?.Trim() ?? "").Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (list.Length > 50 || list.Any(x => x.Length > 200)) throw new BoardException("match lists take up to 50 entries of up to 200 characters");
            return list;
        }
    }

    /// <summary>Kill switch. Pausing applies at once for any admin (it only tightens); resuming is loosening and needs a second admin.</summary>
    public async Task<object> SetPauseAsync(Principal p, AutomationPauseInput input, CancellationToken ct = default)
    {
        RequireAdmin(p);
        if (input.Paused)
        {
            var state = new AutomationPause(true, p.Handle, DateTimeOffset.UtcNow, input.Reason.Trim());
            await new KvState(db).SetAsync(PauseKey, state, ct);
            // A pending resume no longer matches what the admins are looking at.
            await using (var sup = db.Command("update policy_changes set status = 'superseded' where target = 'automation:paused' and status = 'pending'"))
                await sup.ExecuteNonQueryAsync(ct);
            Invalidate();
            await audit.WriteAsync(p.Id, "automation.paused", null, new { reason = state.Reason }, ct);
            await board.PostAsync(await system.GetAsync(ct), new PostInput("general",
                $"@{p.Handle} **paused automation**: every request now waits for a person, including kinds with automation rules. Reason: {state.Reason}",
                "status", Json.Element(new { state = "automation_paused" })), system: true, ct);
            return state;
        }
        if (!(await PauseAsync(ct)).Paused) throw BoardException.Conflict("automation is not paused");
        return await ChangeAsync(p, "automation:paused", input.Reason, Json.Element(new { paused = false }), (_, _) => true, ct);
    }

    /// <summary>
    /// Shared change path: under a per-target lock, read the current value, decide tighten or loosen against it (not
    /// against what the caller saw), supersede any older pending change for the target, then apply or file.
    /// </summary>
    private async Task<PolicyChange> ChangeAsync(Principal p, string target, string reason, JsonElement? after, Func<JsonElement?, JsonElement?, bool> isLooser, CancellationToken ct)
    {
        reason = reason.Trim();
        Guid id;
        bool loosening;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await LockAsync(conn, tx, target, ct);
            var before = await CurrentValueAsync(conn, tx, target, ct);
            if (JsonEquals(before, after)) throw new BoardException("nothing to change: that is already the setting");
            loosening = isLooser(before, after);
            await using (var sup = new NpgsqlCommand("update policy_changes set status = 'superseded' where target = @t and status = 'pending'", conn, tx).With("t", target))
                await sup.ExecuteNonQueryAsync(ct);
            await using (var ins = new NpgsqlCommand("""
                insert into policy_changes (target, before, after, loosening, reason, status, requested_by, expires_at, decided_by, decided_at)
                values (@t, @b::jsonb, @a::jsonb, @l, @r, @s, @p, now() + make_interval(secs => @exp), @d, case when @d::uuid is null then null else now() end)
                returning id
                """, conn, tx).With("t", target).With("b", before?.GetRawText()).With("a", after?.GetRawText()).With("l", loosening).With("r", reason)
                .With("s", loosening ? "pending" : "applied").With("p", p.Id).With("exp", file.Automation.ChangeExpiryHours * 3600)
                .With("d", loosening ? null : p.Id))
                id = (Guid)(await ins.ExecuteScalarAsync(ct))!;
            if (!loosening) await ApplyAsync(conn, tx, target, after, p, id, ct);
            await AuditTxAsync(conn, tx, p.Id, loosening ? "policy.change_requested" : "policy.change_applied", target,
                new { change_id = id, before, after, reason, loosening, tightening = !loosening }, ct);
            await tx.CommitAsync(ct);
        }
        Invalidate();
        var change = (await GetChangeAsync(id, ct))!;
        await board.PostAsync(await system.GetAsync(ct), new PostInput("general", loosening
            ? $"@{p.Handle} asked to **loosen policy** ({Label(target)}). A different board admin must approve it on /policy before it applies; it expires at {change.ExpiresAt:yyyy-MM-dd HH:mm} UTC. Reason: {reason}"
            : $"@{p.Handle} **tightened policy** ({Label(target)}); it applies now. Reason: {reason}",
            "status", Json.Element(new { state = loosening ? "policy_change_pending" : "policy_change_applied", change_id = id, target })), system: true, ct);
        return change;
    }

    /// <summary>A second admin approves or denies a pending loosening. The requester can't decide their own change.</summary>
    public async Task<PolicyChange> DecideAsync(Principal p, Guid id, PolicyChangeDecisionInput input, CancellationToken ct = default)
    {
        RequireAdmin(p);
        var c = await GetChangeAsync(id, ct) ?? throw BoardException.NotFound("policy change");
        if (c.RequestedBy == p.Handle) throw BoardException.Forbidden("you asked for this change: a different board admin must decide it");
        if (c.Status != "pending") throw BoardException.Conflict($"change is {c.Status}");
        string status;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await LockAsync(conn, tx, c.Target, ct);
            if (input.Decision == "approve")
            {
                // The setting moved since the request (another change applied): the approver would be judging a stale diff.
                var now = await CurrentValueAsync(conn, tx, c.Target, ct);
                if (!JsonEquals(now, c.Before))
                {
                    await using (var sup = new NpgsqlCommand("update policy_changes set status = 'superseded' where id = @id and status = 'pending'", conn, tx).With("id", id))
                        await sup.ExecuteNonQueryAsync(ct);
                    await tx.CommitAsync(ct);
                    throw BoardException.Conflict("the setting changed since this was requested; ask for the change again");
                }
                if (c.Target.StartsWith("kind:", StringComparison.Ordinal) && Parse<KindSetting>(c.After) is { } s
                    && AutomationRules.OverrideProblems(c.Target[5..], s, file) is { Count: > 0 } problems)
                    throw BoardException.Conflict("this change no longer fits policy.json: " + string.Join("; ", problems));
            }
            status = input.Decision == "approve" ? "applied" : "denied";
            await using (var up = new NpgsqlCommand("""
                update policy_changes set status = @s, decided_by = @p, decided_at = now(), decision_note = @n
                where id = @id and status = 'pending' and requested_by <> @p and expires_at > now() returning id
                """, conn, tx).With("s", status).With("p", p.Id).With("n", input.Note).With("id", id))
                if (await up.ExecuteScalarAsync(ct) is null)
                {
                    await tx.RollbackAsync(ct);
                    throw BoardException.Conflict("change is no longer pending (decided, superseded or expired)");
                }
            if (status == "applied") await ApplyAsync(conn, tx, c.Target, c.After, p, id, ct);
            await AuditTxAsync(conn, tx, p.Id, status == "applied" ? "policy.change_approved" : "policy.change_denied", c.Target,
                new { change_id = id, requested_by = c.RequestedBy, note = input.Note, before = c.Before, after = c.After }, ct);
            await tx.CommitAsync(ct);
        }
        Invalidate();
        await board.PostAsync(await system.GetAsync(ct), new PostInput("general",
            $"@{p.Handle} **{(status == "applied" ? "approved" : "denied")}** @{c.RequestedBy}'s policy change ({Label(c.Target)}){(status == "applied" ? "; it applies now" : "")}.{(input.Note is { Length: > 0 } n ? $" Note: {n}" : "")}",
            "status", Json.Element(new { state = $"policy_change_{status}", change_id = id, target = c.Target })), system: true, ct);
        return (await GetChangeAsync(id, ct))!;
    }

    /// <summary>Recovery timer: pending changes past expires_at become expired (audited).</summary>
    public async Task<int> ExpireChangesAsync(CancellationToken ct = default)
    {
        var expired = new List<(Guid Id, string Target)>();
        await using (var cmd = db.Command("update policy_changes set status = 'expired' where status = 'pending' and expires_at <= now() returning id, target"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) expired.Add((r.GetGuid(0), r.GetString(1)));
        foreach (var (id, target) in expired) await audit.WriteAsync(null, "policy.change_expired", target, new { change_id = id }, ct);
        return expired.Count;
    }

    public async Task<PolicyChange?> GetChangeAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            select c.id, c.target, c.before::text, c.after::text, c.loosening, c.reason, c.status, rp.handle, c.requested_at, c.expires_at,
                   dp.handle, c.decided_at, c.decision_note
            from policy_changes c join principals rp on rp.id = c.requested_by left join principals dp on dp.id = c.decided_by
            where c.id = @id
            """).With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? ReadChange(r) : null;
    }

    // ── storage ────────────────────────────────────────────────────────────────────────────────

    private static async Task LockAsync(NpgsqlConnection conn, NpgsqlTransaction tx, string target, CancellationToken ct)
    {
        await using var lk = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('policy:' || @t))", conn, tx).With("t", target);
        await lk.ExecuteNonQueryAsync(ct);
    }

    private static async Task<JsonElement?> CurrentValueAsync(NpgsqlConnection conn, NpgsqlTransaction tx, string target, CancellationToken ct)
    {
        var (type, key) = Split(target);
        var sql = type switch
        {
            "kind" => "select setting::text from policy_overrides where kind = @k",
            "trigger" => "select jsonb_build_object('playbook_id', playbook_id, 'priority', priority, 'match', match, 'enabled', enabled)::text from playbook_triggers where id = @k",
            _ => $"select jsonb_build_object('paused', coalesce((value ->> 'paused')::boolean, false))::text from kv_state where key = '{PauseKey}'",
        };
        await using var cmd = new NpgsqlCommand(sql, conn, tx).With("k", key);
        var raw = await cmd.ExecuteScalarAsync(ct) as string;
        if (type == "automation") raw ??= """{"paused":false}""";
        return raw is null ? null : JsonDocument.Parse(raw).RootElement.Clone();
    }

    private async Task ApplyAsync(NpgsqlConnection conn, NpgsqlTransaction tx, string target, JsonElement? after, Principal p, Guid changeId, CancellationToken ct)
    {
        var (type, key) = Split(target);
        NpgsqlCommand cmd;
        switch (type)
        {
            case "kind" when after is { } a:
                cmd = new NpgsqlCommand("""
                    insert into policy_overrides (kind, setting, updated_by, change_id) values (@k, @s::jsonb, @p, @c)
                    on conflict (kind) do update set setting = excluded.setting, version = policy_overrides.version + 1,
                      updated_by = excluded.updated_by, updated_at = now(), change_id = excluded.change_id
                    """, conn, tx).With("k", key).With("s", a.GetRawText()).With("p", p.Id).With("c", changeId);
                break;
            case "kind":
                cmd = new NpgsqlCommand("delete from policy_overrides where kind = @k", conn, tx).With("k", key);
                break;
            case "trigger" when Parse<TriggerSetting>(after) is { } t:
                cmd = new NpgsqlCommand("""
                    insert into playbook_triggers (id, playbook_id, source, match, priority, enabled, updated_by) values (@k, @pb, @src, @m::jsonb, @pr, @en, @p)
                    on conflict (id) do update set playbook_id = excluded.playbook_id, match = excluded.match, priority = excluded.priority,
                      enabled = excluded.enabled, version = playbook_triggers.version + 1, updated_by = excluded.updated_by, updated_at = now()
                    """, conn, tx).With("k", key).With("pb", t.PlaybookId).With("src", key.StartsWith(FilePrefix, StringComparison.Ordinal) ? "file" : "custom")
                    .With("m", JsonSerializer.Serialize(t.Match, Json.Options)).With("pr", t.Priority).With("en", t.Enabled).With("p", p.Id);
                break;
            case "trigger":
                cmd = new NpgsqlCommand("delete from playbook_triggers where id = @k", conn, tx).With("k", key);
                break;
            default:
                cmd = new NpgsqlCommand($"""
                    insert into kv_state (key, value) values ('{PauseKey}', @v::jsonb)
                    on conflict (key) do update set value = excluded.value, updated_at = now()
                    """, conn, tx).With("v", JsonSerializer.Serialize(new AutomationPause(false, p.Handle, DateTimeOffset.UtcNow, "resumed"), Json.Options));
                break;
        }
        await using (cmd) await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task AuditTxAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Guid actor, string evt, string subject, object detail, CancellationToken ct)
    {
        await using var au = new NpgsqlCommand("insert into audit_log (actor_id, event, subject, detail) values (@a, @e, @s, @d)", conn, tx)
            .With("a", actor).With("e", evt).With("s", subject).WithJson("d", detail);
        await au.ExecuteNonQueryAsync(ct);
    }

    private static (string Type, string Key) Split(string target)
    {
        var i = target.IndexOf(':');
        return (target[..i], target[(i + 1)..]);
    }

    private static string Label(string target) => Split(target) switch
    {
        ("kind", var k) => $"action {k}",
        ("trigger", var t) => $"playbook trigger {t}",
        _ => "resume automation",
    };

    private static T? Parse<T>(JsonElement? e) where T : class =>
        e is { ValueKind: JsonValueKind.Object } v ? v.Deserialize<T>(Json.Options) : null;

    internal static bool JsonEquals(JsonElement? a, JsonElement? b) =>
        (a, b) switch
        {
            (null, null) => true,
            ({ } x, { } y) => JsonElement.DeepEquals(x, y),
            _ => false,
        };
}
