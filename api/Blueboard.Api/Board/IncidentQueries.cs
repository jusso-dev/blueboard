using System.Text.Json;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Board;

public sealed record IncidentListItem(
    Guid Id, string GraphId, string DisplayName, string Severity, string Status, string? Classification,
    int AlertCount, string? WebUrl, int MessageCount);

public sealed record QueueRow(
    Guid Id, string GraphId, string DisplayName, string Severity, string Status, string? WebUrl, int AlertCount,
    string? Verdict, double? VerdictConfidence, string? VerdictBy,
    int OpenAsks, int HumanAsks, int PendingActions, string[] ActiveClaims,
    DateTimeOffset LastActivityAt, DateTimeOffset CreatedAt, bool Mine, bool NeedsHuman);

/// <summary>Incident lists for the web app: the rail and pickers, the Queue home page, and the incident summary.</summary>
public sealed class IncidentQueries(Db db, BoardService board, PlaybookSet playbooks)
{
    public async Task<IReadOnlyList<IncidentListItem>> ListAsync(int limit, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            select id, graph_id, display_name, severity, status, classification, alert_count, web_url,
                   (select count(*)::int from messages m where m.incident_id = incidents.id) as message_count
            from incidents order by coalesce(updated_at_src, first_seen_at) desc limit @limit
            """).With("limit", Math.Clamp(limit, 1, 200));
        var list = new List<IncidentListItem>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new IncidentListItem(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4),
                r.Get<string>("classification"), r.GetInt32(6), r.Get<string>("web_url"), r.GetInt32(8)));
        return list;
    }

    /// <summary>
    /// The Queue: open incidents (Defender status not resolved), one statement with per-incident aggregates.
    /// Sorted "needs a human" first: pending approvals, then unclaimed questions that @mention a person, then
    /// severity, then last activity. Open asks exclude playbook checklist steps (those show as progress instead).
    /// </summary>
    public async Task<IReadOnlyList<QueueRow>> QueueAsync(Principal me, bool includeResolved = false, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            with humans as (select coalesce(array_agg(handle), '{}') as handles from principals where kind = 'human' and enabled)
            select i.id, i.graph_id, i.display_name, i.severity, i.status, i.web_url, i.alert_count,
                   v.classification as verdict, v.confidence as verdict_confidence, v.handle as verdict_by,
                   coalesce(m.open_asks, 0) as open_asks, coalesce(m.human_asks, 0) as human_asks,
                   coalesce(a.pending, 0) as pending_actions, coalesce(c.handles, '{}') as active_claims,
                   greatest(m.last_at, a.last_at, i.updated_at_src, i.first_seen_at) as last_activity_at,
                   coalesce(i.created_at_src, i.first_seen_at) as created_at,
                   coalesce(m.mine, false) as mine,
                   (coalesce(a.pending, 0) > 0 or coalesce(m.human_asks, 0) > 0) as needs_human
            from incidents i
            cross join humans h
            left join lateral (
              select count(*) filter (where x.open_ask)::int as open_asks,
                     count(*) filter (where x.open_ask and x.mentions && h.handles)::int as human_asks,
                     max(x.created_at) as last_at,
                     bool_or(x.author_id = @me or @handle = any(x.mentions)) as mine
              from (select mm.created_at, mm.author_id, mm.mentions,
                           mm.type = 'question' and not coalesce(mm.payload ? 'checklist', false)
                             and (mm.claim_state = 'open' or (mm.claim_state = 'claimed' and mm.claim_expires_at < now())) as open_ask
                    from messages mm where mm.incident_id = i.id) x
            ) m on true
            left join lateral (
              select count(*) filter (where status in ('pending_approval', 'approved_once'))::int as pending, max(updated_at) as last_at
              from actions where incident_id = i.id
            ) a on true
            left join lateral (
              select array_agg(distinct p.handle order by p.handle) as handles
              from messages cm join principals p on p.id = cm.claimed_by
              where cm.incident_id = i.id and cm.claim_state = 'claimed' and cm.claim_expires_at > now()
            ) c on true
            left join lateral (
              select vm.payload->>'classification' as classification, (vm.payload->>'confidence')::float8 as confidence, vp.handle
              from messages vm join principals vp on vp.id = vm.author_id
              where vm.incident_id = i.id and vm.type = 'verdict'
              order by vm.seq desc limit 1
            ) v on true
            where @all or lower(i.status) <> 'resolved'
            order by needs_human desc, coalesce(a.pending, 0) > 0 desc, coalesce(m.human_asks, 0) > 0 desc,
                     case lower(i.severity) when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end desc,
                     last_activity_at desc
            limit 500
            """).With("me", me.Id).With("handle", me.Handle).With("all", includeResolved);
        var list = new List<QueueRow>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new QueueRow(
                r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.Get<string>("web_url"), r.GetInt32(6),
                r.Get<string>("verdict"), r.Get<double?>("verdict_confidence"), r.Get<string>("verdict_by"),
                r.GetInt32(10), r.GetInt32(11), r.GetInt32(12), r.GetFieldValue<string[]>(13),
                r.GetFieldValue<DateTimeOffset>(14), r.GetFieldValue<DateTimeOffset>(15), r.GetBoolean(16), r.GetBoolean(17)));
        return list;
    }

    /// <summary>The summary panel for one incident, rolled up from its stored messages and actions.</summary>
    public async Task<IncidentSummaryResult> SummaryAsync(Guid incidentId, CancellationToken ct = default)
    {
        SummaryIncident incident;
        string? playbookId;
        await using (var cmd = db.Command("""
            select i.graph_id, i.display_name, i.severity, i.status, i.data::text, ip.playbook_id
            from incidents i left join incident_playbooks ip on ip.incident_id = i.id where i.id = @id
            """).With("id", incidentId))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (!await r.ReadAsync(ct)) throw BoardException.NotFound("incident");
            incident = new SummaryIncident(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), JsonDocument.Parse(r.GetString(4)).RootElement.Clone());
            playbookId = r.Get<string>("playbook_id");
        }

        var messages = await board.ListForIncidentAsync(incidentId, ct);

        var actions = new List<SummaryActionInput>();
        await using (var cmd = db.Command("""
            select a.id, a.kind, a.status, p.handle, a.request_message_id, a.created_at
            from actions a join principals p on p.id = a.requested_by where a.incident_id = @id order by a.created_at
            """).With("id", incidentId))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                actions.Add(new SummaryActionInput(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.Get<Guid?>("request_message_id"), r.GetFieldValue<DateTimeOffset>(5)));

        return IncidentSummary.Build(incident, messages, actions, playbookId is null ? null : playbooks.Get(playbookId), DateTimeOffset.UtcNow);
    }
}
