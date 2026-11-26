using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Npgsql;

namespace Blueboard.Api.Board;

/// <summary>What counts as a reaction: exactly one emoji (ZWJ sequences, skin tones, flags and keycaps included).</summary>
public static class Emoji
{
    public const int MaxLength = 32;
    public const int MaxPerMessage = 20;

    /// <summary>The emoji, trimmed, or a 400 naming what is wrong with it.</summary>
    public static string Validate(string? emoji) => Check(emoji?.Trim()) is { } why ? throw new BoardException(why) : emoji!.Trim();

    /// <summary>Null when <paramref name="s"/> is one emoji; otherwise why not.</summary>
    public static string? Check(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "emoji is required";
        if (s.Length > MaxLength) return $"emoji must be at most {MaxLength} characters";
        if (new StringInfo(s).LengthInTextElements != 1) return "emoji must be a single emoji";
        var runes = s.EnumerateRunes().ToList();
        // Keycaps (1️⃣, #️⃣, *️⃣) are the only emoji that start with an ASCII character.
        var keycap = runes.Count >= 2 && runes[^1].Value == 0x20E3 && runes[0].Value is (>= '0' and <= '9') or '#' or '*';
        var symbol = false;
        for (var i = 0; i < runes.Count; i++)
        {
            var r = runes[i];
            if (i == 0 && keycap) continue;
            if (r.IsAscii || Rune.IsLetter(r) || Rune.IsDigit(r) || Rune.IsWhiteSpace(r) || Rune.IsControl(r)) return "emoji must be an emoji, not text";
            var cat = Rune.GetUnicodeCategory(r);
            if (cat == UnicodeCategory.OtherSymbol) { symbol = true; continue; }
            // A few emoji are math symbols (↔️, ↕️): only with the emoji presentation selector, so plain ∑ stays text.
            if (cat == UnicodeCategory.MathSymbol && i + 1 < runes.Count && runes[i + 1].Value == 0xFE0F) { symbol = true; continue; }
            // Joiners and modifiers that build one emoji out of several: skin tones (Sk), ZWJ, variation selectors,
            // tag characters (subdivision flags), the keycap mark.
            if (cat == UnicodeCategory.ModifierSymbol || r.Value is 0x200D or 0xFE0E or 0xFE0F or 0x20E3 or (>= 0xE0020 and <= 0xE007F)) continue;
            return "emoji must be an emoji, not text";
        }
        return symbol || keycap ? null : "emoji must be an emoji, not text";
    }
}

public sealed partial class BoardService
{
    /// <summary>Reactions on each of these messages, one query for the page. Messages with none are absent.</summary>
    internal async Task<Dictionary<Guid, Reaction[]>> ReactionsForAsync(IReadOnlyCollection<Guid> ids, CancellationToken ct)
    {
        var map = new Dictionary<Guid, Reaction[]>();
        if (ids.Count == 0) return map;
        await using var cmd = db.Command($"""
            select r.message_id, r.emoji, count(*)::int,
                   (array_agg(p.handle order by r.created_at, p.handle))[1:{Emoji.MaxPerMessage}],
                   min(r.created_at) as first_at
            from message_reactions r join principals p on p.id = r.principal_id
            where r.message_id = any(@ids)
            group by r.message_id, r.emoji
            order by r.message_id, first_at, r.emoji
            """).With("ids", ids.ToArray());
        var rows = new List<(Guid Id, Reaction R)>();
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                rows.Add((r.GetGuid(0), new Reaction(r.GetString(1), r.GetInt32(2), r.GetFieldValue<string[]>(3))));
        foreach (var g in rows.GroupBy(x => x.Id)) map[g.Key] = g.Select(x => x.R).ToArray();
        return map;
    }

    private async Task<List<Message>> WithReactionsAsync(List<Message> list, CancellationToken ct)
    {
        if (list.Count == 0) return list;
        var reactions = await ReactionsForAsync(list.Select(m => m.Id).Distinct().ToList(), ct);
        if (reactions.Count == 0) return list;
        for (var i = 0; i < list.Count; i++)
            if (reactions.TryGetValue(list[i].Id, out var rs)) list[i] = list[i] with { Reactions = rs };
        return list;
    }

    /// <summary>
    /// Add or remove the caller's reaction. Idempotent: adding twice or removing a reaction that isn't there changes
    /// nothing. A 21st distinct emoji on one message is refused. Agents spend a token from their post bucket; people
    /// don't. Not audited: reactions carry no authority and would flood audit_log.
    /// </summary>
    public async Task<Reaction[]> ReactAsync(Principal p, Guid messageId, string emoji, bool remove, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        emoji = Emoji.Validate(emoji);
        if (!p.IsHuman && limiter is not null) await limiter.TakeAsync(p, "post", ct);
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            // Serialises reactions on one message so the distinct-emoji cap holds under concurrent adds.
            await using (var lk = new NpgsqlCommand("select 1 from messages where id = @id for no key update", conn, tx).With("id", messageId))
                if (await lk.ExecuteScalarAsync(ct) is null) throw BoardException.NotFound("message");
            if (remove)
            {
                await using var del = new NpgsqlCommand("delete from message_reactions where message_id = @m and principal_id = @p and emoji = @e", conn, tx)
                    .With("m", messageId).With("p", p.Id).With("e", emoji);
                await del.ExecuteNonQueryAsync(ct);
            }
            else
            {
                await using (var cnt = new NpgsqlCommand("""
                    select count(distinct emoji)::int, bool_or(emoji = @e) from message_reactions where message_id = @m
                    """, conn, tx).With("m", messageId).With("e", emoji))
                await using (var r = await cnt.ExecuteReaderAsync(ct))
                {
                    await r.ReadAsync(ct);
                    var distinct = r.GetInt32(0);
                    var present = !r.IsDBNull(1) && r.GetBoolean(1);
                    if (!present && distinct >= Emoji.MaxPerMessage)
                        throw new BoardException($"a message can have at most {Emoji.MaxPerMessage} different emoji reactions");
                }
                await using var ins = new NpgsqlCommand("insert into message_reactions (message_id, principal_id, emoji) values (@m, @p, @e) on conflict do nothing", conn, tx)
                    .With("m", messageId).With("p", p.Id).With("e", emoji);
                await ins.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        return (await ReactionsForAsync([messageId], ct)).GetValueOrDefault(messageId) ?? [];
    }

    // ── typing ────────────────────────────────────────────────────────────────────────────────

    /// <summary>A person's indicator lasts this long; the web app re-sends while they type.</summary>
    public static readonly TimeSpan HumanTypingFor = TimeSpan.FromSeconds(6);
    /// <summary>An agent's indicator lasts this long; the SDK renews it every 10 seconds while a handler runs.</summary>
    public static readonly TimeSpan AgentTypingFor = TimeSpan.FromSeconds(30);

    private static readonly ConcurrentDictionary<(Guid, Guid, Guid?), DateTimeOffset> TypingWrites = new();

    private readonly record struct TypingScope(Guid ChannelId, Guid? IncidentId, Guid? RootId);

    /// <summary>A thread's root message id (a reply id resolves to its root), with its channel and incident.</summary>
    private async Task<TypingScope> ThreadScopeAsync(Guid id, CancellationToken ct)
    {
        await using var cmd = db.Command("""
            select coalesce(r.channel_id, m.channel_id), coalesce(r.incident_id, m.incident_id), coalesce(m.parent_id, m.id)
            from messages m left join messages r on r.id = m.parent_id where m.id = @id
            """).With("id", id);
        await using var rd = await cmd.ExecuteReaderAsync(ct);
        if (!await rd.ReadAsync(ct)) throw BoardException.NotFound("message");
        return new TypingScope(rd.GetGuid(0), rd.IsDBNull(1) ? null : rd.GetGuid(1), rd.GetGuid(2));
    }

    /// <summary>The channel an incident is discussed in: its incident message's channel, else #incidents.</summary>
    private async Task<Guid> IncidentChannelAsync(Guid incidentId, CancellationToken ct)
    {
        await using var cmd = db.Command("""
            select coalesce(
              (select m.channel_id from messages m where m.incident_id = @i and m.type = 'incident' and m.parent_id is null order by m.seq limit 1),
              (select id from channels where name = 'incidents'))
            """).With("i", incidentId);
        return await cmd.ExecuteScalarAsync(ct) is Guid id ? id : throw BoardException.NotFound("channel #incidents");
    }

    /// <summary>POST /api/typing: the caller is typing in a thread, or in a channel's or incident's top-level composer.</summary>
    public async Task TypingAsync(Principal p, TypingInput input, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        TypingScope scope;
        if (input.Thread is { } thread) scope = await ThreadScopeAsync(thread, ct);
        else if (input.Incident is { Length: > 0 } inc)
        {
            var incidentId = (await ResolveIncidentAsync(inc, ct))!.Value;
            scope = new TypingScope(input.Channel is { Length: > 0 } ch ? await ChannelIdAsync(ch, ct) : await IncidentChannelAsync(incidentId, ct), incidentId, null);
        }
        else if (input.Channel is { Length: > 0 } channel) scope = new TypingScope(await ChannelIdAsync(channel, ct), null, null);
        else throw new BoardException("give a thread, an incident or a channel");

        // The trivial limit: one write per person and composer per second. A browser sends one every few seconds.
        var key = (p.Id, scope.ChannelId, scope.RootId);
        var now = DateTimeOffset.UtcNow;
        if (TypingWrites.TryGetValue(key, out var last) && now - last < TimeSpan.FromSeconds(1)) return;
        TypingWrites[key] = now;
        if (TypingWrites.Count > 10_000) TypingWrites.Clear();
        await UpsertTypingAsync(p, scope, HumanTypingFor, ct);
    }

    /// <summary>set_typing: an agent working on a message shows as typing in its thread (active), or stops (inactive).</summary>
    public async Task<object> SetTypingAsync(Principal p, Guid messageId, bool active, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        var scope = await ThreadScopeAsync(messageId, ct);
        if (active)
        {
            await UpsertTypingAsync(p, scope, AgentTypingFor, ct);
            return new { active = true, thread = scope.RootId, until = DateTimeOffset.UtcNow + AgentTypingFor };
        }
        await using var del = db.Command("delete from typing where principal_id = @p and channel_id = @c and root_id is not distinct from @r")
            .With("p", p.Id).With("c", scope.ChannelId).With("r", scope.RootId);
        await del.ExecuteNonQueryAsync(ct);
        return new { active = false, thread = scope.RootId };
    }

    private async Task UpsertTypingAsync(Principal p, TypingScope s, TimeSpan duration, CancellationToken ct)
    {
        // Expired rows are swept on the way in; nothing else needs a timer.
        await using var cmd = db.Command("""
            with swept as (delete from typing where until < now() - interval '1 minute' and principal_id <> @p)
            insert into typing (principal_id, channel_id, incident_id, root_id, until)
            values (@p, @c, @i, @r, now() + make_interval(secs => @secs))
            on conflict (principal_id, channel_id, coalesce(root_id, '00000000-0000-0000-0000-000000000000'::uuid))
            do update set until = excluded.until, incident_id = excluded.incident_id
            """).With("p", p.Id).With("c", s.ChannelId).With("i", s.IncidentId).With("r", s.RootId).With("secs", duration.TotalSeconds);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    /// <summary>
    /// GET /api/typing. thread=X: typing in thread X. Otherwise incident=Y: typing anywhere on incident Y (in channel C
    /// too, when given). Otherwise channel=C: typing a top-level post in C, not in one of its threads. Never the caller.
    /// </summary>
    public async Task<IReadOnlyList<Author>> WhoIsTypingAsync(Principal me, TypingQuery q, CancellationToken ct = default)
    {
        var where = new List<string> { "t.until > now()", "t.principal_id <> @me", "p.enabled" };
        await using var cmd = db.Command("");
        cmd.With("me", me.Id);
        if (q.Thread is { } thread)
        {
            where.Add("t.root_id = @root");
            cmd.With("root", (await ThreadScopeAsync(thread, ct)).RootId);
        }
        else if (q.Incident is { Length: > 0 } inc)
        {
            where.Add("t.incident_id = @inc");
            cmd.With("inc", (await ResolveIncidentAsync(inc, ct))!.Value);
            if (q.Channel is { Length: > 0 } ch) { where.Add("t.channel_id = @ch"); cmd.With("ch", await ChannelIdAsync(ch, ct)); }
        }
        else if (q.Channel is { Length: > 0 } channel)
        {
            where.Add("t.channel_id = @ch and t.root_id is null");
            cmd.With("ch", await ChannelIdAsync(channel, ct));
        }
        else throw new BoardException("give a thread, an incident or a channel");
        cmd.CommandText = $"""
            select distinct p.handle, p.display_name, p.kind
            from typing t join principals p on p.id = t.principal_id
            where {string.Join(" and ", where)}
            order by p.display_name, p.handle limit 20
            """;
        var list = new List<Author>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(new Author(r.GetString(0), r.GetString(1), r.GetString(2)));
        return list;
    }
}
