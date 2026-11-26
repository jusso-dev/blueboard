using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Npgsql;

namespace Blueboard.Api.Board;

/// <summary>
/// Shared SOC memory store backed by PostgreSQL so every agent and human analyst shares durable environment context,
/// known-benign baselines, asset notes, procedures and temporary notices (e.g. change freezes).
/// Security boundary: agents may write/update unverified memories and archive their own unverified entries; only human
/// principals can verify, pin, modify verified memories, or archive another principal's memory.
/// </summary>
public sealed partial class MemoryService(Db db, Audit audit, BoardService board, RateLimiter? limiter = null)
{
    public static readonly string[] Categories = ["environment", "baseline", "asset", "threat", "procedure", "preference", "general"];

    [GeneratedRegex(@"^[a-z0-9][a-z0-9._/\-]{1,119}$")]
    private static partial Regex KeyPattern();

    private const string MemorySelect = """
        select m.id, m.key, m.category, m.title, m.content, m.tags, m.entities, m.confidence,
               m.verified, vb.handle as verified_by, m.verified_at, m.pinned, m.archived,
               m.source_incident_id, i.graph_id as source_incident_graph_id, m.source_message_id,
               m.expires_at,
               cb.handle as c_handle, cb.display_name as c_name, cb.kind as c_kind,
               ub.handle as u_handle, ub.display_name as u_name, ub.kind as u_kind,
               m.created_at, m.updated_at
        from shared_memories m
        join principals cb on cb.id = m.created_by
        join principals ub on ub.id = m.updated_by
        left join principals vb on vb.id = m.verified_by
        left join incidents i on i.id = m.source_incident_id
        """;

    public static string NormaliseKey(string raw)
    {
        var k = Regex.Replace((raw ?? "").Trim().ToLowerInvariant(), @"[\s]+", "-").Trim('/');
        if (k.Contains("..", StringComparison.Ordinal) || k.Contains("//", StringComparison.Ordinal) || !KeyPattern().IsMatch(k))
            throw new BoardException("memory key must be 2–120 lowercase characters (a-z, 0-9, -, _, ., /)");
        return k;
    }

    public static string[] NormaliseTokens(IEnumerable<string>? items, int maxItems, int maxLen = 120) =>
        (items ?? [])
            .Where(s => s is not null && !s.Any(char.IsControl))
            .Select(s => Regex.Replace(s.Trim(), @"\s+", " ").ToLowerInvariant())
            .Where(s => s.Length >= 1 && s.Length <= maxLen)
            .Distinct()
            .Take(maxItems)
            .ToArray();

    private static SharedMemory ReadRow(NpgsqlDataReader r) => new(
        r.GetGuid(0),
        r.GetString(1),
        r.GetString(2),
        r.GetString(3),
        r.GetString(4),
        r.GetFieldValue<string[]>(5),
        r.GetFieldValue<string[]>(6),
        r.IsDBNull(7) ? null : r.GetDouble(7),
        r.GetBoolean(8),
        r.IsDBNull(9) ? null : r.GetString(9),
        r.IsDBNull(10) ? null : r.GetFieldValue<DateTimeOffset>(10),
        r.GetBoolean(11),
        r.GetBoolean(12),
        r.IsDBNull(13) ? null : r.GetGuid(13),
        r.IsDBNull(14) ? null : r.GetString(14),
        r.IsDBNull(15) ? null : r.GetGuid(15),
        r.IsDBNull(16) ? null : r.GetFieldValue<DateTimeOffset>(16),
        new Author(r.GetString(17), r.GetString(18), r.GetString(19)),
        new Author(r.GetString(20), r.GetString(21), r.GetString(22)),
        r.GetFieldValue<DateTimeOffset>(23),
        r.GetFieldValue<DateTimeOffset>(24));

    public async Task<SharedMemory?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"{MemorySelect} where m.id = @id").With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? ReadRow(r) : null;
    }

    public async Task<SharedMemory?> GetByKeyAsync(string key, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"{MemorySelect} where m.key = @k").With("k", key);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? ReadRow(r) : null;
    }

    public async Task<IReadOnlyList<SharedMemory>> ListAsync(MemoryQuery q, CancellationToken ct = default)
    {
        var limit = Math.Clamp(q.Limit, 1, 200);
        var where = new List<string>();
        if (!q.IncludeArchived)
            where.Add("not m.archived and (m.expires_at is null or m.expires_at > now())");
        if (!string.IsNullOrWhiteSpace(q.Category))
        {
            var cat = q.Category.Trim().ToLowerInvariant();
            if (!Categories.Contains(cat)) throw new BoardException($"category must be one of {string.Join(", ", Categories)}");
            where.Add("m.category = @cat");
        }
        if (q.VerifiedOnly) where.Add("m.verified");
        if (!string.IsNullOrWhiteSpace(q.Tag)) where.Add("m.tags @> array[@tag]::text[]");
        if (!string.IsNullOrWhiteSpace(q.Entity)) where.Add("(m.entities @> array[@ent]::text[] or m.content ilike @ent_like or m.title ilike @ent_like)");
        if (!string.IsNullOrWhiteSpace(q.Q))
            where.Add("(m.tsv @@ websearch_to_tsquery('english', @q) or m.key ilike @q_like or m.title ilike @q_like or m.content ilike @q_like or @q_lower = any(m.entities) or @q_lower = any(m.tags))");

        var sql = MemorySelect
            + (where.Count > 0 ? " where " + string.Join(" and ", where) : "")
            + (!string.IsNullOrWhiteSpace(q.Q)
                ? " order by m.pinned desc, m.verified desc, ts_rank(m.tsv, websearch_to_tsquery('english', @q)) desc, m.updated_at desc"
                : " order by m.pinned desc, m.verified desc, m.updated_at desc")
            + " limit @lim";

        await using var cmd = db.Command(sql).With("lim", limit);
        if (!string.IsNullOrWhiteSpace(q.Category)) cmd.With("cat", q.Category.Trim().ToLowerInvariant());
        if (!string.IsNullOrWhiteSpace(q.Tag)) cmd.With("tag", q.Tag.Trim().ToLowerInvariant());
        if (!string.IsNullOrWhiteSpace(q.Entity))
        {
            var ent = q.Entity.Trim().ToLowerInvariant();
            cmd.With("ent", ent).With("ent_like", $"%{EscapeLike(ent)}%");
        }
        if (!string.IsNullOrWhiteSpace(q.Q))
        {
            var qt = q.Q.Trim();
            cmd.With("q", qt).With("q_lower", qt.ToLowerInvariant()).With("q_like", $"%{EscapeLike(qt)}%");
        }
        var list = new List<SharedMemory>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(ReadRow(r));
        return list;
    }

    public async Task<SharedMemory> RememberAsync(Principal me, MemoryInput input, CancellationToken ct = default)
    {
        me.Require(Roles.Poster);
        if (limiter is not null) await limiter.TakeAsync(me, "post", ct);

        var key = NormaliseKey(input.Key);
        var category = (input.Category ?? "general").Trim().ToLowerInvariant();
        if (!Categories.Contains(category)) throw new BoardException($"category must be one of {string.Join(", ", Categories)}");

        var title = (input.Title ?? "").Trim();
        var content = (input.Content ?? "").Trim();
        if (title.Length is < 3 or > 200 || title.Any(char.IsControl)) throw new BoardException("title must be 3–200 characters on one line");
        if (content.Length is < 5 or > 4000 || content.Contains('\0')) throw new BoardException("content must be 5–4000 characters");
        if (input.Confidence is < 0 or > 1) throw new BoardException("confidence must be between 0 and 1");
        if (input.ExpiresInHours is < 1 or > 8760) throw new BoardException("expires_in_hours must be between 1 and 8760");
        if (BoardService.DetectSecretLeak(key) is not null || BoardService.DetectSecretLeak(title) is not null || BoardService.DetectSecretLeak(content) is not null)
            throw new BoardException("refusing to store raw credentials, private keys or bearer tokens in shared memory");

        var tags = NormaliseTokens(input.Tags, 20, 60);
        var entities = NormaliseTokens(input.Entities, 30, 200);
        var incidentId = await board.ResolveIncidentAsync(input.Incident, ct);
        DateTimeOffset? expiresAt = input.ExpiresInHours is { } hrs ? DateTimeOffset.UtcNow.AddHours(hrs) : null;

        var existing = await GetByKeyAsync(key, ct);
        if (existing is not null && !me.IsHuman && existing.Verified)
            throw BoardException.Forbidden("only a human analyst can edit a human-verified memory (create a separate key or ask an analyst to update it)");

        // Humans can verify/pin directly; agent-written memories always start unverified and unpinned.
        var verified = me.IsHuman && (input.Verified ?? true);
        var pinned = me.IsHuman && (input.Pinned ?? existing?.Pinned ?? false);
        Guid? verifiedBy = verified ? me.Id : null;
        DateTimeOffset? verifiedAt = verified ? DateTimeOffset.UtcNow : null;

        await using var cmd = db.Command("""
            insert into shared_memories (
              key, category, title, content, tags, entities, confidence,
              verified, verified_by, verified_at, pinned, archived,
              source_incident_id, source_message_id, expires_at, created_by, updated_by
            ) values (
              @key, @cat, @title, @content, @tags, @entities, @conf,
              @ver, @vby, @vat, @pin, false,
              @inc, @msg, @exp, @me, @me
            )
            on conflict (key) do update set
              category = excluded.category,
              title = excluded.title,
              content = excluded.content,
              tags = excluded.tags,
              entities = excluded.entities,
              confidence = excluded.confidence,
              verified = excluded.verified,
              verified_by = excluded.verified_by,
              verified_at = excluded.verified_at,
              pinned = excluded.pinned,
              archived = false,
              source_incident_id = coalesce(excluded.source_incident_id, shared_memories.source_incident_id),
              source_message_id = coalesce(excluded.source_message_id, shared_memories.source_message_id),
              expires_at = excluded.expires_at,
              updated_by = excluded.updated_by,
              updated_at = now()
            returning id
            """)
            .With("key", key).With("cat", category).With("title", title).With("content", content)
            .With("tags", tags).With("entities", entities).With("conf", input.Confidence)
            .With("ver", verified).With("vby", verifiedBy).With("vat", verifiedAt).With("pin", pinned)
            .With("inc", incidentId).With("msg", input.SourceMessageId).With("exp", expiresAt).With("me", me.Id);

        var id = (Guid)(await cmd.ExecuteScalarAsync(ct))!;
        await audit.WriteAsync(me.Id, existing is null ? "memory.saved" : "memory.updated", key,
            new { id, category, verified, pinned, entities = entities.Length, tags = tags.Length }, ct);
        return (await GetByIdAsync(id, ct))!;
    }

    public async Task<SharedMemory> SetVerificationAsync(Principal me, Guid id, MemoryVerifyInput input, CancellationToken ct = default)
    {
        me.Require(Roles.Poster);
        if (!me.IsHuman) throw BoardException.Forbidden("only human analysts can verify or pin shared memories");
        var existing = await GetByIdAsync(id, ct) ?? throw BoardException.NotFound("shared memory");

        var verified = input.Verified ?? existing.Verified;
        var pinned = input.Pinned ?? existing.Pinned;
        await using var cmd = db.Command("""
            update shared_memories
            set verified = @ver,
                verified_by = case when @ver then @me else null end,
                verified_at = case when @ver then now() else null end,
                pinned = @pin,
                updated_by = @me,
                updated_at = now()
            where id = @id
            """)
            .With("id", id).With("ver", verified).With("pin", pinned).With("me", me.Id);
        await cmd.ExecuteNonQueryAsync(ct);

        await audit.WriteAsync(me.Id, verified ? "memory.verified" : "memory.unverified", existing.Key, new { id, verified, pinned }, ct);
        return (await GetByIdAsync(id, ct))!;
    }

    public async Task<object> ForgetAsync(Principal me, Guid? id, string? key, string? reason, CancellationToken ct = default)
    {
        me.Require(Roles.Poster);
        SharedMemory? existing = id is { } gid
            ? await GetByIdAsync(gid, ct)
            : !string.IsNullOrWhiteSpace(key) ? await GetByKeyAsync(NormaliseKey(key), ct)
            : throw new BoardException("provide id or key");
        if (existing is null) throw BoardException.NotFound("shared memory");
        if (!me.IsHuman && (existing.Verified || existing.CreatedBy.Handle != me.Handle))
            throw BoardException.Forbidden("agents can only archive their own unverified memories");

        await using var cmd = db.Command("update shared_memories set archived = true, updated_by = @me, updated_at = now() where id = @id")
            .With("id", existing.Id).With("me", me.Id);
        await cmd.ExecuteNonQueryAsync(ct);

        var cleanReason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim()[..Math.Min(reason.Trim().Length, 300)];
        await audit.WriteAsync(me.Id, "memory.archived", existing.Key, new { id = existing.Id, reason = cleanReason }, ct);
        return new { id = existing.Id, key = existing.Key, archived = true };
    }

    private static string EscapeLike(string s) => s.Replace(@"\", @"\\").Replace("%", @"\%").Replace("_", @"\_");
}
