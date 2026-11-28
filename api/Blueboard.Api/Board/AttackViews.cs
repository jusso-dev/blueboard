using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;

namespace Blueboard.Api.Board;

/// <summary>
/// Loads an incident's stored data, messages and actions for the attack timeline and attack graph (both computed on
/// read by <see cref="IncidentTimeline"/> and <see cref="IncidentGraph"/>), and appends agent-reported timeline events
/// as an attributed finding message.
/// </summary>
public sealed class AttackViews(Db db, BoardService board, Policy policy)
{
    private async Task<(Guid Id, string GraphId, JsonElement Data)> LoadIncidentAsync(string reference, CancellationToken ct)
    {
        var id = await board.ResolveIncidentAsync(reference, ct) ?? throw BoardException.NotFound("incident");
        await using var cmd = db.Command("select graph_id, data::text from incidents where id = @id").With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) throw BoardException.NotFound("incident");
        return (id, r.GetString(0), JsonDocument.Parse(r.GetString(1)).RootElement.Clone());
    }

    public async Task<IncidentTimelineResult> TimelineAsync(string reference, string? entity = null, string? source = null, int limit = 500, CancellationToken ct = default)
    {
        var (id, graphId, data) = await LoadIncidentAsync(reference, ct);
        var messages = await board.ListForIncidentAsync(id, ct);

        var approvals = new Dictionary<Guid, List<(string, DateTimeOffset)>>();
        await using (var cmd = db.Command("""
            select x.action_id, p.handle, x.at from action_approvals x join principals p on p.id = x.approver_id
            join actions a on a.id = x.action_id where a.incident_id = @id order by x.at
            """).With("id", id))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
            {
                if (!approvals.TryGetValue(r.GetGuid(0), out var list)) approvals[r.GetGuid(0)] = list = [];
                list.Add((r.GetString(1), r.GetFieldValue<DateTimeOffset>(2)));
            }

        var actions = new List<TimelineActionInput>();
        await using (var cmd = db.Command("""
            select a.id, a.kind, a.status, rp.handle, a.created_at, dp.handle as decided_by,
                   case when a.status = 'expired' then a.updated_at else a.decided_at end as decided_at,
                   a.finished_at, a.request_message_id, a.params::text, coalesce(a.result->>'dry_run', '') = 'true' as dry_run, a.error
            from actions a join principals rp on rp.id = a.requested_by left join principals dp on dp.id = a.decided_by
            where a.incident_id = @id order by a.created_at limit 500
            """).With("id", id))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                actions.Add(new TimelineActionInput(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<DateTimeOffset>(4),
                    r.Get<string>("decided_by"), r.Get<DateTimeOffset?>("decided_at"), r.Get<DateTimeOffset?>("finished_at"), r.Get<Guid?>("request_message_id"),
                    JsonDocument.Parse(r.GetString(9)).RootElement.Clone(), approvals.GetValueOrDefault(r.GetGuid(0)) ?? [], r.GetBoolean(10), r.Get<string>("error")));

        return IncidentTimeline.Build(id, graphId, data, messages, actions, entity, source, limit);
    }

    /// <summary>Protected entries are named only for admins (like GET /api/policy); everyone else sees the flag.</summary>
    public async Task<IncidentGraphResult> GraphAsync(Principal caller, string reference, CancellationToken ct = default)
    {
        var (id, graphId, data) = await LoadIncidentAsync(reference, ct);
        var messages = await board.ListForIncidentAsync(id, ct);
        var actions = new List<GraphActionInput>();
        await using (var cmd = db.Command("select kind, status, params::text, held_at is not null from actions where incident_id = @id limit 500").With("id", id))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                actions.Add(new GraphActionInput(r.GetString(0), r.GetString(1), JsonDocument.Parse(r.GetString(2)).RootElement.Clone(), r.GetBoolean(3)));
        return IncidentGraph.Build(id, graphId, data, messages, actions, policy, caller.Has(Roles.Admin));
    }

    /// <summary>
    /// add_timeline_events: one finding in the incident thread with payload.events, so the events are attributed to the
    /// caller, rate limited, secret-scanned and audited like any post, and show on the timeline as reported.
    /// </summary>
    public async Task<object> AddEventsAsync(Principal me, AddTimelineEventsInput input, CancellationToken ct = default)
    {
        me.Require(Roles.Poster);
        if (input.Events is not { Length: > 0 and <= Payloads.MaxTimelineEvents })
            throw new BoardException($"events must list 1–{Payloads.MaxTimelineEvents} events");
        var incidentId = await board.ResolveIncidentAsync(input.Incident, ct) ?? throw BoardException.NotFound("incident");

        var channel = "incidents";
        var parent = input.ParentId;
        if (parent is { } pid)
        {
            var root = await board.GetAsync(pid, ct) ?? throw BoardException.NotFound("parent message");
            if (root.IncidentId != incidentId) throw new BoardException("parent_id is not on this incident");
            channel = root.Channel;
        }
        else
        {
            await using var rc = db.Command("""
                select m.id from messages m join channels c on c.id = m.channel_id
                where m.incident_id = @i and m.type = 'incident' and m.parent_id is null and c.name = 'incidents'
                order by m.seq asc limit 1
                """).With("i", incidentId);
            parent = await rc.ExecuteScalarAsync(ct) as Guid?;
        }

        var events = input.Events.Select(e => new Dictionary<string, object?>
        {
            ["ts"] = e.Ts.ToUniversalTime().ToString("O"), ["entity"] = e.Entity, ["action"] = e.Action, ["source"] = e.Source, ["ref"] = e.Ref,
        }).ToArray();
        var payload = new Dictionary<string, object?>
        {
            ["events"] = events,
            ["entities"] = input.Events.Select(e => e.Entity.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(50).ToArray(),
        };
        if (input.Confidence is { } c) payload["confidence"] = c;
        if (input.Query is { Length: > 0 } q) payload["evidence"] = q;
        var span = $"{input.Events.Min(e => e.Ts):yyyy-MM-dd HH:mm} to {input.Events.Max(e => e.Ts):yyyy-MM-dd HH:mm} UTC";
        var body = $"{input.Summary.Trim()}\n\nAdded {input.Events.Length} timeline event(s), {span}.";
        var posted = await board.PostAsync(me, new PostInput(channel, body, "finding", Json.Element(payload), parent, incidentId.ToString()), ct: ct);
        return new { message_id = posted.Id, incident_id = incidentId, events_added = input.Events.Length };
    }
}
