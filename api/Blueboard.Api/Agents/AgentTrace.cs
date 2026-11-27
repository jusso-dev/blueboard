using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blueboard.Api.Agents;

/// <summary>One recorded MCP call, as the "Agent trace" panel shows it.</summary>
public sealed record TraceCall(
    long Id, string Handle, string Kind, string Tool, string Status, JsonElement? Args, string? Kql, string? Error,
    int DurationMs, int ResultBytes, Guid? MessageId, Guid? ClaimMessageId, Guid? IncidentId, bool IncidentInferred, DateTimeOffset At);

/// <summary>One finished call, handed to <see cref="AgentTrace.RecordAsync"/> by the MCP hook.</summary>
public sealed record TraceEntry(
    Principal Principal, string Tool, string Status, JsonElement? Arguments, string? Error, int DurationMs, int ResultBytes, Guid? ResultMessageId);

/// <summary>
/// "How did the agent get here": every MCP tool call, recorded server-side by the hook in BoardTools. Stores a redacted,
/// size-capped argument summary (TraceRedactor), the KQL for hunting calls, status, duration and result size; never
/// the result itself. Each call is linked to what it was for when the board can tell: the message it named, the claim
/// the agent held at the time, and that message's incident. Kept TRACE_RETENTION_DAYS (default 30), then deleted.
/// </summary>
public sealed class AgentTrace(Db db, ILogger<AgentTrace>? log = null)
{
    private readonly ILogger _log = log ?? NullLogger<AgentTrace>.Instance;

    /// <summary>Records one call. Never throws: losing a trace row must not fail the agent's call.</summary>
    public async Task RecordAsync(TraceEntry e, CancellationToken ct = default)
    {
        try
        {
            var summary = TraceRedactor.Summarise(e.Arguments);
            var kql = TraceRedactor.Kql(e.Tool, e.Arguments);
            var named = NamedMessage(e.Arguments) ?? e.ResultMessageId;
            var incidentRef = e.Arguments is { ValueKind: JsonValueKind.Object } a && a.TryGetProperty("incident", out var inc) && inc.ValueKind == JsonValueKind.String ? inc.GetString() : null;
            var error = e.Error is null ? null : TraceRedactor.Text(e.Error.Length > 300 ? e.Error[..300] : e.Error);
            // Links, in one statement: the message the call names (if it exists), the claim the agent holds right now
            // (latest claimed message), and the incident from the arguments, the named message or the claim.
            await using var cmd = db.Command("""
                with named as (select id, incident_id from messages where id = @named),
                claim as (select id, incident_id from messages where claimed_by = @p and claim_state = 'claimed'
                            and claim_expires_at >= now() order by claimed_at desc limit 1),
                inc as (select id from incidents where @iref::text is not null and (graph_id = @iref or id::text = @iref) limit 1)
                insert into agent_tool_calls (principal_id, tool, status, args_summary, kql, error, duration_ms, result_bytes,
                                              message_id, claim_message_id, incident_id, incident_inferred)
                select @p, @t, @s, @a, @k, @e, @d, @rb,
                       (select id from named), (select id from claim),
                       coalesce((select id from inc), (select incident_id from named), (select incident_id from claim)),
                       (select id from inc) is null and (select incident_id from named) is null and (select incident_id from claim) is not null
                """).With("p", e.Principal.Id).With("t", e.Tool).With("s", e.Status).WithJson("a", summary).With("k", kql).With("e", error)
                    .With("d", e.DurationMs).With("rb", e.ResultBytes).With("named", named).With("iref", incidentRef);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "trace for {Tool} not recorded", e.Tool);
        }
    }

    /// <summary>A message id the arguments name: message_id, parent_id, claim_message_id or on_behalf_of (first found).</summary>
    internal static Guid? NamedMessage(JsonElement? args)
    {
        if (args is not { ValueKind: JsonValueKind.Object } a) return null;
        foreach (var k in new[] { "message_id", "parent_id", "claim_message_id", "on_behalf_of" })
            if (a.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String && Guid.TryParse(v.GetString(), out var g)) return g;
        return null;
    }

    private const string Select = """
        select c.id, p.handle, p.kind, c.tool, c.status, c.args_summary::text, c.kql, c.error, c.duration_ms, c.result_bytes,
               c.message_id, c.claim_message_id, c.incident_id, c.incident_inferred, c.created_at
        from agent_tool_calls c join principals p on p.id = c.principal_id
        """;

    private static async Task<List<TraceCall>> ReadAsync(Npgsql.NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<TraceCall>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new TraceCall(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4),
                r.IsDBNull(5) ? null : JsonDocument.Parse(r.GetString(5)).RootElement.Clone(), r.Get<string>("kql"), r.Get<string>("error"),
                r.GetInt32(8), r.GetInt32(9), r.Get<Guid?>("message_id"), r.Get<Guid?>("claim_message_id"), r.Get<Guid?>("incident_id"),
                r.GetBoolean(13), r.GetFieldValue<DateTimeOffset>(14)));
        return list;
    }

    /// <summary>
    /// The calls that led to one agent message: those made while the agent held a claim on the message's thread root
    /// (or the message itself), plus the calls in the 15 minutes before it on the same incident, plus calls that
    /// produced or named it. Oldest first, at most 200.
    /// </summary>
    public async Task<IReadOnlyList<TraceCall>> ForMessageAsync(Guid messageId, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"""
            with m as (select id, author_id, incident_id, coalesce(parent_id, id) as root, created_at from messages where id = @id)
            {Select}
            cross join m
            where c.principal_id = m.author_id
              and c.created_at <= m.created_at + interval '5 seconds'
              and c.created_at >= m.created_at - interval '2 hours'
              and (c.message_id in (m.id, m.root) or c.claim_message_id in (m.id, m.root)
                   or (m.incident_id is not null and c.incident_id = m.incident_id and c.created_at >= m.created_at - interval '15 minutes'))
            order by c.created_at asc, c.id asc
            limit 200
            """).With("id", messageId);
        return await ReadAsync(cmd, ct);
    }

    /// <summary>Every agent call linked to an incident, oldest first (at most 500).</summary>
    public async Task<IReadOnlyList<TraceCall>> ForIncidentAsync(Guid incidentId, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"{Select} where c.incident_id = @i and p.kind = 'agent' order by c.created_at asc, c.id asc limit 500").With("i", incidentId);
        return await ReadAsync(cmd, ct);
    }

    /// <summary>One agent's latest calls, newest first.</summary>
    public async Task<IReadOnlyList<TraceCall>> ForAgentAsync(string handle, int limit, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"{Select} where p.handle = @h order by c.created_at desc, c.id desc limit @n").With("h", handle).With("n", Math.Clamp(limit, 1, 500));
        return await ReadAsync(cmd, ct);
    }

    /// <summary>Deletes trace rows older than <paramref name="days"/>. Returns rows deleted.</summary>
    public async Task<int> PurgeAsync(int days, CancellationToken ct = default)
    {
        if (days < 1) throw new BoardException("trace retention must be at least 1 day");
        var total = 0;
        // Batches, so a large backlog never holds one long lock.
        while (true)
        {
            await using var cmd = db.Command("""
                delete from agent_tool_calls where id in (select id from agent_tool_calls where created_at < now() - make_interval(days => @d) limit 5000)
                """).With("d", days);
            var n = await cmd.ExecuteNonQueryAsync(ct);
            total += n;
            if (n < 5000) return total;
        }
    }
}
