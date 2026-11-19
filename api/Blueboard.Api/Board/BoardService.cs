using Blueboard.Contracts;
using System.Text.Json;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Npgsql;

namespace Blueboard.Api.Board;

/// <summary>Channels, messages, threads and claims. All SQL is parameterised.</summary>
public sealed partial class BoardService(Db db, Audit audit, Settings settings, RateLimiter? limiter = null)
{
    internal const string MessageSelect = """
        select m.id, m.seq::text as seq, c.name as channel,
               a.handle as a_handle, a.display_name as a_name, a.kind as a_kind,
               m.parent_id, m.incident_id, i.graph_id as incident_graph_id,
               m.type, m.body, m.payload::text as payload, m.mentions,
               case when m.claim_state = 'claimed' and m.claim_expires_at < now() then 'open' else m.claim_state end as claim_state,
               case when m.claim_state = 'claimed' and m.claim_expires_at < now() then null else cp.handle end as claimed_by,
               m.claim_expires_at, m.created_at,
               (select count(*)::int from messages r where r.parent_id = m.id) as reply_count
        from messages m
        join channels c on c.id = m.channel_id
        join principals a on a.id = m.author_id
        left join principals cp on cp.id = m.claimed_by
        left join incidents i on i.id = m.incident_id
        """;

    [GeneratedRegex(@"(?:^|[^\w@])@([a-z0-9][a-z0-9-]{1,40})")]
    private static partial Regex MentionRegex();

    public static string[] ParseMentions(string body) =>
        MentionRegex().Matches(body).Select(m => m.Groups[1].Value).Distinct().ToArray();

    internal static Message ReadMessage(NpgsqlDataReader r, string? snippet = null)
    {
        var payload = r.Get<string>("payload");
        return new Message(
            r.GetGuid(r.GetOrdinal("id")),
            r.GetString(r.GetOrdinal("seq")),
            r.GetString(r.GetOrdinal("channel")),
            new Author(r.GetString(r.GetOrdinal("a_handle")), r.GetString(r.GetOrdinal("a_name")), r.GetString(r.GetOrdinal("a_kind"))),
            r.Get<Guid?>("parent_id"),
            r.Get<Guid?>("incident_id"),
            r.Get<string>("incident_graph_id"),
            r.GetString(r.GetOrdinal("type")),
            r.GetString(r.GetOrdinal("body")),
            payload is null ? null : JsonDocument.Parse(payload).RootElement.Clone(),
            r.GetFieldValue<string[]>(r.GetOrdinal("mentions")),
            r.GetString(r.GetOrdinal("claim_state")),
            r.Get<string>("claimed_by"),
            r.Get<DateTimeOffset?>("claim_expires_at"),
            r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("created_at")),
            r.GetInt32(r.GetOrdinal("reply_count")),
            snippet);
    }

    private async Task<List<Message>> QueryMessagesAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<Message>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(ReadMessage(r));
        return list;
    }

    public async Task<IReadOnlyList<ChannelInfo>> ListChannelsAsync(CancellationToken ct = default)
    {
        await using var cmd = db.Command("select c.name, c.topic, (select max(seq)::text from messages m where m.channel_id = c.id) from channels c order by c.name");
        var list = new List<ChannelInfo>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(new ChannelInfo(r.GetString(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2)));
        return list;
    }

    public async Task<IReadOnlyList<Participant>> ListParticipantsAsync(CancellationToken ct = default)
    {
        await using var cmd = db.Command("select handle, display_name, kind, roles, description, last_seen_at from principals where enabled order by kind, handle");
        var list = new List<Participant>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new Participant(r.GetString(0), r.GetString(1), r.GetString(2), r.GetFieldValue<string[]>(3), r.Get<string>("description"), r.Get<DateTimeOffset?>("last_seen_at")));
        return list;
    }

    private async Task<Guid> ChannelIdAsync(string name, CancellationToken ct)
    {
        await using var cmd = db.Command("select id from channels where name = @n").With("n", name);
        return await cmd.ExecuteScalarAsync(ct) is Guid id ? id : throw BoardException.NotFound($"channel #{name}");
    }

    /// <summary>Checks a channel exists (404 otherwise).</summary>
    public Task<Guid> ResolveChannelAsync(string name, CancellationToken ct = default) => ChannelIdAsync(name, ct);

    /// <summary>Board incident UUID or Defender incident id → board incident id.</summary>
    public async Task<Guid?> ResolveIncidentAsync(string? reference, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(reference)) return null;
        await using var cmd = Guid.TryParse(reference, out var g)
            ? db.Command("select id from incidents where id = @g or graph_id = @r").With("g", g).With("r", reference)
            : db.Command("select id from incidents where graph_id = @r").With("r", reference);
        return await cmd.ExecuteScalarAsync(ct) is Guid id ? id : throw BoardException.NotFound($"incident {reference}");
    }

    /// <summary>
    /// Feed ordering lock. Every message insert takes it (transaction-scoped) before its seq is allocated, so
    /// messages commit in seq order. A reader therefore never sees seq n+1 while seq n is still in flight, and an
    /// agent's after_seq cursor can't skip a message (issue #4). Board write volume is low; the lock is held only
    /// for the insert transaction.
    /// </summary>
    internal const long FeedLock = 7340003;

    public async Task<Message> PostAsync(Principal author, PostInput input, bool system = false, CancellationToken ct = default)
    {
        if (!system && limiter is not null) await limiter.TakeAsync(author, "post", ct);
        await using var conn = await db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        var id = await PostInTransactionAsync(conn, tx, author, input, system, ct);
        await tx.CommitAsync(ct);
        return (await GetAsync(id, ct))!;
    }

    /// <summary>
    /// Validates and inserts a message inside the caller's transaction (the broker uses this so an action and its
    /// board message commit together). Returns the new message id; the message becomes visible on commit.
    /// </summary>
    internal async Task<Guid> PostInTransactionAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Principal author, PostInput input, bool system, CancellationToken ct)
    {
        var type = input.Type ?? "chat";
        if (!system)
        {
            author.Require(Roles.Poster);
            if (!MessageTypes.Postable.Contains(type)) throw new BoardException($"type must be one of {string.Join(", ", MessageTypes.Postable)}");
        }
        if (string.IsNullOrWhiteSpace(input.Body) || input.Body.Length > 20000) throw new BoardException("body must be 1–20000 characters");
        if (input.Channel.Length is 0 or > 41) throw new BoardException("invalid channel");
        var payload = input.Payload is { ValueKind: not JsonValueKind.Undefined and not JsonValueKind.Null } p
            ? Payloads.Validate(type, p)
            : (JsonElement?)null;

        // Lookups run on this transaction's connection. Borrowing a second pooled connection while holding this one
        // can exhaust the pool under load: every connection held by a transaction that waits for another.
        Guid channelId;
        await using (var cc = new NpgsqlCommand("select id from channels where name = @n", conn, tx).With("n", input.Channel))
            channelId = await cc.ExecuteScalarAsync(ct) is Guid cid ? cid : throw BoardException.NotFound($"channel #{input.Channel}");
        Guid? incidentId = null;
        if (!string.IsNullOrWhiteSpace(input.Incident))
        {
            await using var ic = Guid.TryParse(input.Incident, out var g)
                ? new NpgsqlCommand("select id from incidents where id = @g or graph_id = @r", conn, tx).With("g", g).With("r", input.Incident)
                : new NpgsqlCommand("select id from incidents where graph_id = @r", conn, tx).With("r", input.Incident);
            incidentId = await ic.ExecuteScalarAsync(ct) is Guid iid ? iid : throw BoardException.NotFound($"incident {input.Incident}");
        }
        if (input.ParentId is { } parentId)
        {
            await using var pc = new NpgsqlCommand("select channel_id, incident_id, parent_id from messages where id = @id", conn, tx).With("id", parentId);
            await using var r = await pc.ExecuteReaderAsync(ct);
            if (!await r.ReadAsync(ct)) throw BoardException.NotFound("parent message");
            if (!r.IsDBNull(2)) throw new BoardException("reply to the thread root, not to a reply");
            if (r.GetGuid(0) != channelId) throw new BoardException("reply must be in the parent's channel");
            incidentId ??= r.Get<Guid?>("incident_id");
        }

        await using (var lk = new NpgsqlCommand("select pg_advisory_xact_lock(@k)", conn, tx).With("k", FeedLock))
            await lk.ExecuteNonQueryAsync(ct);
        await using var cmd = new NpgsqlCommand("""
            insert into messages (channel_id, author_id, parent_id, incident_id, type, body, payload, mentions)
            values (@c, @a, @p, @i, @t, @b, @pl, @m) returning id
            """, conn, tx).With("c", channelId).With("a", author.Id).With("p", input.ParentId).With("i", incidentId)
                .With("t", type).With("b", input.Body).WithJson("pl", payload).With("m", ParseMentions(input.Body));
        return (Guid)(await cmd.ExecuteScalarAsync(ct))!;
    }

    public async Task<Message?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"{MessageSelect} where m.id = @id").With("id", id);
        return (await QueryMessagesAsync(cmd, ct)).FirstOrDefault();
    }

    public async Task<FeedResult> ReadFeedAsync(FeedQuery q, CancellationToken ct = default)
    {
        var limit = Math.Clamp(q.Limit, 1, 200);
        var incidentId = await ResolveIncidentAsync(q.Incident, ct);
        var where = new List<string> { "true" };
        await using var cmd = db.Command("");
        if (q.Channel is { } ch) { where.Add("c.name = @ch"); cmd.With("ch", ch); }
        if (incidentId is { } inc) { where.Add("m.incident_id = @inc"); cmd.With("inc", inc); }
        if (q.AfterSeq is { } after) { where.Add("m.seq > @after"); cmd.With("after", after); }
        if (q.BeforeSeq is { } before) { where.Add("m.seq < @before"); cmd.With("before", before); }
        if (q.Types is { Length: > 0 } types) { where.Add("m.type = any(@types)"); cmd.With("types", types); }
        if (q.Mentioning is { } who) { where.Add("@who = any(m.mentions)"); cmd.With("who", who); }
        if (q.RootsOnly) where.Add("m.parent_id is null");
        if (q.OpenRequests)
            where.Add("m.type in ('question','finding','ioc') and (m.claim_state = 'open' or (m.claim_state = 'claimed' and m.claim_expires_at < now()))");
        cmd.With("limit", limit);
        var w = string.Join(" and ", where);
        // Forward paging (after_seq) reads oldest-first so agents process in order; otherwise the newest page.
        cmd.CommandText = q.AfterSeq is not null
            ? $"{MessageSelect} where {w} order by m.seq asc limit @limit"
            : $"select * from ({MessageSelect} where {w} order by m.seq desc limit @limit) t order by seq::bigint asc";
        var rows = await QueryMessagesAsync(cmd, ct);
        return new FeedResult(rows, rows.Count > 0 ? rows[^1].Seq : q.AfterSeq?.ToString());
    }

    public async Task<ThreadResult> GetThreadAsync(Guid rootId, CancellationToken ct = default)
    {
        var root = await GetAsync(rootId, ct) ?? throw BoardException.NotFound("message");
        await using var cmd = db.Command($"{MessageSelect} where m.parent_id = @id order by m.seq asc").With("id", rootId);
        return new ThreadResult(root, await QueryMessagesAsync(cmd, ct));
    }

    /// <summary>Claim a question/finding/ioc. Atomic: succeeds only if open, or the previous lease expired, or you hold it.</summary>
    public async Task<Message> ClaimAsync(Principal p, Guid id, int? leaseSeconds = null, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        if (limiter is not null) await limiter.TakeAsync(p, "claim", ct);
        var lease =Math.Clamp(leaseSeconds ?? settings.ClaimLeaseSeconds, 30, 3600);
        await using var cmd = db.Command("""
            update messages set claim_state = 'claimed', claimed_by = @p, claimed_at = now(),
                   claim_expires_at = now() + make_interval(secs => @lease)
            where id = @id and type = any(@claimable)
              and (claim_state = 'open' or (claim_state = 'claimed' and (claim_expires_at < now() or claimed_by = @p)))
            returning id
            """).With("p", p.Id).With("lease", (double)lease).With("id", id).With("claimable", MessageTypes.Claimable);
        if (await cmd.ExecuteScalarAsync(ct) is null)
        {
            var existing = await GetAsync(id, ct) ?? throw BoardException.NotFound("message");
            if (!MessageTypes.Claimable.Contains(existing.Type)) throw new BoardException($"{existing.Type} messages are not claimable");
            throw BoardException.Conflict($"already {existing.ClaimState} by @{existing.ClaimedBy}");
        }
        await audit.WriteAsync(p.Id, "message.claimed", id.ToString(), new { lease }, ct);
        return (await GetAsync(id, ct))!;
    }

    /// <summary>Extend a lease you hold (and haven't let expire). Someone else's claim, or none, is a conflict.</summary>
    public async Task<Message> RenewClaimAsync(Principal p, Guid id, int? leaseSeconds = null, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        var lease = Math.Clamp(leaseSeconds ?? settings.ClaimLeaseSeconds, 30, 3600);
        await using var cmd = db.Command("""
            update messages set claim_expires_at = now() + make_interval(secs => @lease)
            where id = @id and claim_state = 'claimed' and claimed_by = @p and claim_expires_at >= now()
            returning id
            """).With("lease", (double)lease).With("id", id).With("p", p.Id);
        if (await cmd.ExecuteScalarAsync(ct) is null)
        {
            var existing = await GetAsync(id, ct) ?? throw BoardException.NotFound("message");
            throw BoardException.Conflict(existing.ClaimState == "claimed" ? $"claimed by @{existing.ClaimedBy}, not you" : "you do not hold a claim on this message (it may have expired: claim it again)");
        }
        await audit.WriteAsync(p.Id, "message.claim_renewed", id.ToString(), new { lease }, ct);
        return (await GetAsync(id, ct))!;
    }

    public async Task<Message> SettleClaimAsync(Principal p, Guid id, string outcome, CancellationToken ct = default)
    {
        if (outcome is not ("done" or "release")) throw new BoardException("outcome must be done or release");
        var state = outcome == "done" ? "done" : "open";
        await using var cmd = db.Command("""
            update messages set claim_state = @s,
                   claimed_by = case when @s = 'done' then claimed_by else null end,
                   claim_expires_at = null
            where id = @id and claim_state = 'claimed' and claimed_by = @p returning id
            """).With("s", state).With("id", id).With("p", p.Id);
        if (await cmd.ExecuteScalarAsync(ct) is null) throw BoardException.Conflict("you do not hold a claim on this message");
        await audit.WriteAsync(p.Id, $"message.claim_{outcome}", id.ToString(), null, ct);
        return (await GetAsync(id, ct))!;
    }

    /// <summary>The typed messages an incident summary rolls up (verdicts, IOCs, findings, questions), oldest first.</summary>
    public async Task<IReadOnlyList<Message>> ListForIncidentAsync(Guid incidentId, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"""
            {MessageSelect} where m.incident_id = @id and m.type in ('verdict', 'ioc', 'finding', 'question')
            order by m.seq asc limit 2000
            """).With("id", incidentId);
        return await QueryMessagesAsync(cmd, ct);
    }

    public async Task<IReadOnlyList<Message>> GetManyAsync(IReadOnlyList<Guid> ids, CancellationToken ct = default)
    {
        if (ids.Count == 0) return [];
        await using var cmd = db.Command($"{MessageSelect} where m.id = any(@ids)").With("ids", ids.ToArray());
        return await QueryMessagesAsync(cmd, ct);
    }
}
