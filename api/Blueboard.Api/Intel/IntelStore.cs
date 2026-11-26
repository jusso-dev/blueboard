using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Npgsql;

namespace Blueboard.Api.Intel;

/// <summary>One normalised intel row, with the keys it can be looked up by.</summary>
public sealed record TiRecord(
    string Source, string Key, string Kind, string? Title, string? Severity, string? Url, string SourceUrl, JsonObject Data,
    DateTimeOffset? PublishedAt, DateTimeOffset? UpdatedAt, DateTimeOffset RetrievedAt, IReadOnlyList<(string Kind, string Value)> Keys,
    bool Found = true);

public sealed record StoredRecord(
    Guid Id, string Source, string Key, string Kind, string? Title, string? Severity, string? Url, string SourceUrl, JsonElement Data,
    DateTimeOffset? PublishedAt, DateTimeOffset? UpdatedAt, DateTimeOffset RetrievedAt, bool Found);

public sealed record SourceStatus(string Id, bool Enabled, DateTimeOffset? LastFetchAt, string? LastStatus, string? LastError, DateTimeOffset? DataAsOf);

public sealed record Watch(Guid Id, string Kind, string Value, bool Enabled, string Origin, string? Label, DateTimeOffset? LastSeenAt);

/// <summary>Postgres access for threat intel: records, keys, source status, watches, rate budgets and post idempotence.</summary>
public sealed class IntelStore(Db db)
{
    private const string RecordCols = "r.id, r.source, r.key, r.kind, r.title, r.severity, r.url, r.source_url, r.data::text, r.published_at, r.updated_at, r.retrieved_at, r.found";

    private static StoredRecord Read(NpgsqlDataReader r) => new(
        r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.Get<string>("title"), r.Get<string>("severity"), r.Get<string>("url"),
        r.GetString(7), JsonDocument.Parse(r.GetString(8)).RootElement.Clone(), r.Get<DateTimeOffset?>("published_at"), r.Get<DateTimeOffset?>("updated_at"),
        r.GetFieldValue<DateTimeOffset>(11), r.GetBoolean(12));

    /// <summary>Bulk upsert in one transaction. Returns the keys that were new to the store.</summary>
    public async Task<IReadOnlySet<string>> UpsertManyAsync(IReadOnlyList<TiRecord> records, CancellationToken ct = default)
    {
        var created = new HashSet<string>();
        // Feeds can list the same id twice; the last copy wins.
        records = records.GroupBy(r => (r.Source, r.Key)).Select(g => g.Last()).ToList();
        if (records.Count == 0) return created;
        await using var conn = await db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        foreach (var chunk in records.Chunk(500))
        {
            var rows = new JsonArray();
            var keys = new JsonArray();
            foreach (var r in chunk)
            {
                rows.Add(new JsonObject
                {
                    ["source"] = r.Source, ["key"] = r.Key, ["kind"] = r.Kind, ["title"] = Cap(r.Title, 500), ["severity"] = Cap(r.Severity, 50),
                    ["url"] = r.Url, ["source_url"] = r.SourceUrl, ["data"] = r.Data.DeepClone(), ["published_at"] = r.PublishedAt?.ToString("O"),
                    ["updated_at"] = r.UpdatedAt?.ToString("O"), ["retrieved_at"] = r.RetrievedAt.ToString("O"), ["found"] = r.Found,
                });
                foreach (var (k, v) in r.Keys.Distinct())
                    if (v.Length is > 0 and <= 300) keys.Add(new JsonObject { ["source"] = r.Source, ["key"] = r.Key, ["key_kind"] = k, ["key_value"] = v });
            }
            var ids = new List<Guid>();
            await using (var cmd = new NpgsqlCommand("""
                insert into ti_records (source, key, kind, title, severity, url, source_url, data, published_at, updated_at, retrieved_at, found)
                select source, key, kind, title, severity, url, source_url, data, published_at, updated_at, retrieved_at, found
                from jsonb_to_recordset(@rows) as x(source text, key text, kind text, title text, severity text, url text, source_url text,
                     data jsonb, published_at timestamptz, updated_at timestamptz, retrieved_at timestamptz, found boolean)
                on conflict (source, key) do update set
                  kind = excluded.kind, title = excluded.title, severity = excluded.severity, url = excluded.url, source_url = excluded.source_url,
                  data = excluded.data, published_at = excluded.published_at, updated_at = excluded.updated_at,
                  retrieved_at = excluded.retrieved_at, found = excluded.found
                returning id, key, (xmax = 0) as inserted
                """, conn, tx).WithJson("rows", rows))
            await using (var rd = await cmd.ExecuteReaderAsync(ct))
                while (await rd.ReadAsync(ct))
                {
                    ids.Add(rd.GetGuid(0));
                    if (rd.GetBoolean(2)) created.Add(rd.GetString(1));
                }
            await using (var del = new NpgsqlCommand("delete from ti_record_keys where record_id = any(@ids)", conn, tx).With("ids", ids.ToArray()))
                await del.ExecuteNonQueryAsync(ct);
            await using (var ins = new NpgsqlCommand("""
                insert into ti_record_keys (record_id, key_kind, key_value)
                select r.id, x.key_kind, x.key_value
                from jsonb_to_recordset(@keys) as x(source text, key text, key_kind text, key_value text)
                join ti_records r on r.source = x.source and r.key = x.key
                on conflict do nothing
                """, conn, tx).WithJson("keys", keys))
                await ins.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
        return created;
    }

    public async Task<int> CountAsync(string source, CancellationToken ct = default)
    {
        await using var cmd = db.Command("select count(*)::int from ti_records where source = @s").With("s", source);
        return (int)(await cmd.ExecuteScalarAsync(ct))!;
    }

    /// <summary>Records from any of the given sources that carry the lookup key.</summary>
    public async Task<IReadOnlyList<StoredRecord>> FindAsync(string keyKind, string keyValue, string[] sources, int limit = 10, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"""
            select {RecordCols} from ti_records r
            where r.source = any(@src) and exists (select 1 from ti_record_keys k where k.record_id = r.id and k.key_kind = @kk and k.key_value = @kv)
            order by coalesce(r.updated_at, r.published_at, r.retrieved_at) desc limit @lim
            """).With("src", sources).With("kk", keyKind).With("kv", keyValue).With("lim", limit);
        return await ListAsync(cmd, ct);
    }

    public async Task<StoredRecord?> GetAsync(string source, string key, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"select {RecordCols} from ti_records r where r.source = @s and r.key = @k").With("s", source).With("k", key);
        return (await ListAsync(cmd, ct)).FirstOrDefault();
    }

    public async Task<IReadOnlyList<StoredRecord>> GetManyAsync(string source, IReadOnlyList<string> keys, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"select {RecordCols} from ti_records r where r.source = @s and r.key = any(@k)").With("s", source).With("k", keys.ToArray());
        return await ListAsync(cmd, ct);
    }

    public async Task<IReadOnlyList<StoredRecord>> RecentAsync(string[] sources, int limit, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"""
            select {RecordCols} from ti_records r where r.source = any(@src) and r.found
            order by coalesce(r.updated_at, r.published_at, r.retrieved_at) desc limit @lim
            """).With("src", sources).With("lim", limit);
        return await ListAsync(cmd, ct);
    }

    /// <summary>Keys of one kind across all stored records (for the daily EPSS batch).</summary>
    public async Task<IReadOnlyList<string>> KeyValuesAsync(string keyKind, string[] excludeSources, int limit, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            select distinct k.key_value from ti_record_keys k join ti_records r on r.id = k.record_id
            where k.key_kind = @kk and not (r.source = any(@ex)) limit @lim
            """).With("kk", keyKind).With("ex", excludeSources).With("lim", limit);
        var list = new List<string>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(r.GetString(0));
        return list;
    }

    private static async Task<IReadOnlyList<StoredRecord>> ListAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<StoredRecord>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(Read(r));
        return list;
    }

    // ── sources ────────────────────────────────────────────────────────────────────────────────
    public async Task SyncSourcesAsync(TiSettings ti, CancellationToken ct = default)
    {
        foreach (var s in Sources.All.Where(s => s.Id != Sources.CveWatch))
        {
            await using var cmd = db.Command("""
                insert into ti_sources (id, name, enabled) values (@id, @n, @e)
                on conflict (id) do update set enabled = excluded.enabled, name = excluded.name
                where ti_sources.enabled is distinct from excluded.enabled or ti_sources.name is distinct from excluded.name
                """).With("id", s.Id).With("n", s.Name).With("e", Sources.Enabled(ti, s.Id));
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    public async Task SetStatusAsync(string id, string status, string? error, DateTimeOffset? dataAsOf = null, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            insert into ti_sources (id, name, last_fetch_at, last_status, last_error, data_as_of, updated_at) values (@id, @id, now(), @st, @er, @asof, now())
            on conflict (id) do update set last_fetch_at = now(), last_status = excluded.last_status, last_error = excluded.last_error,
              data_as_of = coalesce(excluded.data_as_of, ti_sources.data_as_of), updated_at = now()
            """).With("id", id).With("st", status).With("er", Cap(error, 1000)).With("asof", dataAsOf);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyDictionary<string, SourceStatus>> StatusesAsync(CancellationToken ct = default)
    {
        await using var cmd = db.Command("select id, enabled, last_fetch_at, last_status, last_error, data_as_of from ti_sources");
        var map = new Dictionary<string, SourceStatus>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            map[r.GetString(0)] = new SourceStatus(r.GetString(0), r.GetBoolean(1), r.Get<DateTimeOffset?>("last_fetch_at"), r.Get<string>("last_status"),
                r.Get<string>("last_error"), r.Get<DateTimeOffset?>("data_as_of"));
        return map;
    }

    // ── watches ────────────────────────────────────────────────────────────────────────────────
    public async Task<IReadOnlyList<Watch>> WatchesAsync(bool enabledOnly, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"select id, kind, value, enabled, origin, label, last_seen_at from ti_watches {(enabledOnly ? "where enabled" : "")} order by origin, kind, value");
        var list = new List<Watch>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new Watch(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetBoolean(3), r.GetString(4), r.Get<string>("label"), r.Get<DateTimeOffset?>("last_seen_at")));
        return list;
    }

    public async Task<Watch> AddWatchAsync(string kind, string value, string origin, string? label, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            insert into ti_watches (kind, value, origin, label, last_seen_at) values (@k, @v, @o, @l, case when @o = 'inventory' then now() end)
            on conflict (kind, value) do update set
              last_seen_at = case when excluded.origin = 'inventory' then now() else ti_watches.last_seen_at end,
              label = coalesce(ti_watches.label, excluded.label)
            returning id, kind, value, enabled, origin, label, last_seen_at
            """).With("k", kind).With("v", value).With("o", origin).With("l", label);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return new Watch(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetBoolean(3), r.GetString(4), r.Get<string>("label"), r.Get<DateTimeOffset?>("last_seen_at"));
    }

    public async Task<bool> SetWatchEnabledAsync(Guid id, bool enabled, CancellationToken ct = default)
    {
        await using var cmd = db.Command("update ti_watches set enabled = @e where id = @id").With("e", enabled).With("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task<bool> DeleteWatchAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command("delete from ti_watches where id = @id").With("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    // ── findings table (bot & analyst findings tied to tech stack / watchlists) ──────────────────
    private const string FindingCols = """
        f.id, f.title, f.summary, f.severity, f.status, f.confidence, f.tech_stack, f.matched_watches, f.cves,
        f.indicators::text, f.source, f.source_url, f.recommendation,
        a.handle, a.display_name, a.kind, f.message_id, f.dedupe_key, f.created_at, f.updated_at
        """;

    private static Blueboard.Contracts.TiFinding ReadFinding(NpgsqlDataReader r) => new(
        r.GetGuid(0),
        r.GetString(1),
        r.GetString(2),
        r.GetString(3),
        r.GetString(4),
        r.IsDBNull(5) ? null : r.GetDouble(5),
        r.GetFieldValue<string[]>(6),
        r.GetFieldValue<string[]>(7),
        r.GetFieldValue<string[]>(8),
        JsonSerializer.Deserialize<Blueboard.Contracts.TiFindingIndicator[]>(r.GetString(9), Blueboard.Contracts.BoardJson.Options) ?? [],
        r.GetString(10),
        r.Get<string>("source_url"),
        r.Get<string>("recommendation"),
        new Blueboard.Contracts.Author(r.GetString(13), r.GetString(14), r.GetString(15)),
        r.Get<Guid?>("message_id"),
        r.Get<string>("dedupe_key"),
        r.GetFieldValue<DateTimeOffset>(18),
        r.GetFieldValue<DateTimeOffset>(19));

    public async Task<Blueboard.Contracts.TiFinding?> GetFindingAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command($"select {FindingCols} from ti_findings f join principals a on a.id = f.author_id where f.id = @id").With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? ReadFinding(r) : null;
    }

    public async Task<IReadOnlyList<Blueboard.Contracts.TiFinding>> ListFindingsAsync(Blueboard.Contracts.TiFindingsQuery q, CancellationToken ct = default)
    {
        var where = new List<string> { "true" };
        await using var cmd = db.Command("");
        switch (q.Status)
        {
            case null or "" or "all": break;
            case "open": where.Add("f.status in ('new', 'reviewing')"); break;
            default: where.Add("f.status = @st"); cmd.With("st", q.Status); break;
        }
        if (!string.IsNullOrWhiteSpace(q.Severity)) { where.Add("f.severity = @sev"); cmd.With("sev", q.Severity); }
        if (!string.IsNullOrWhiteSpace(q.Stack))
        {
            var stack = q.Stack.Trim().ToLowerInvariant();
            where.Add("(@stack = any(f.tech_stack) or exists (select 1 from unnest(f.matched_watches) mw where lower(mw) = @stack or lower(mw) like '%:' || @stack))");
            cmd.With("stack", stack);
        }
        if (!string.IsNullOrWhiteSpace(q.Cve))
        {
            var cve = Indicators.NormaliseCve(q.Cve) ?? q.Cve.Trim().ToUpperInvariant();
            where.Add("@cve = any(f.cves)");
            cmd.With("cve", cve);
        }
        if (!string.IsNullOrWhiteSpace(q.Q))
        {
            var needle = q.Q.Trim().ToLowerInvariant();
            where.Add("(strpos(lower(f.title), @q) > 0 or strpos(lower(f.summary), @q) > 0 or strpos(lower(f.source), @q) > 0 or exists (select 1 from unnest(f.tech_stack) ts where strpos(lower(ts), @q) > 0) or exists (select 1 from unnest(f.cves) cv where strpos(lower(cv), @q) > 0))");
            cmd.With("q", needle);
        }
        cmd.With("lim", Math.Clamp(q.Limit, 1, 200));
        cmd.CommandText = $"""
            select {FindingCols} from ti_findings f join principals a on a.id = f.author_id
            where {string.Join(" and ", where)}
            order by case f.status when 'new' then 0 when 'reviewing' then 1 when 'mitigated' then 2 else 3 end,
                     case f.severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end,
                     f.updated_at desc
            limit @lim
            """;
        var list = new List<Blueboard.Contracts.TiFinding>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(ReadFinding(r));
        return list;
    }

    public async Task<(Guid Id, bool Created, Guid? ExistingMessageId)> UpsertFindingAsync(
        Guid authorId, string title, string summary, string severity, double? confidence,
        string[] techStack, string[] matchedWatches, string[] cves, Blueboard.Contracts.TiFindingIndicator[] indicators,
        string source, string? sourceUrl, string? recommendation, string? dedupeKey, CancellationToken ct = default)
    {
        var sql = dedupeKey is null
            ? """
              insert into ti_findings (title, summary, severity, confidence, tech_stack, matched_watches, cves, indicators, source, source_url, recommendation, author_id)
              values (@t, @s, @sev, @conf, @ts, @mw, @cves, @ind, @src, @url, @rec, @au)
              returning id, true as created, message_id
              """
            : """
              insert into ti_findings (title, summary, severity, confidence, tech_stack, matched_watches, cves, indicators, source, source_url, recommendation, author_id, dedupe_key)
              values (@t, @s, @sev, @conf, @ts, @mw, @cves, @ind, @src, @url, @rec, @au, @dk)
              on conflict (dedupe_key) do update set
                title = excluded.title, summary = excluded.summary, severity = excluded.severity,
                confidence = coalesce(excluded.confidence, ti_findings.confidence),
                tech_stack = excluded.tech_stack, matched_watches = excluded.matched_watches,
                cves = excluded.cves, indicators = excluded.indicators,
                source = excluded.source, source_url = coalesce(excluded.source_url, ti_findings.source_url),
                recommendation = coalesce(excluded.recommendation, ti_findings.recommendation),
                updated_at = now()
              returning id, (xmax = 0) as created, message_id
              """;
        await using var cmd = db.Command(sql)
            .With("t", title).With("s", summary).With("sev", severity).With("conf", confidence)
            .With("ts", techStack).With("mw", matchedWatches).With("cves", cves).WithJson("ind", indicators)
            .With("src", source).With("url", sourceUrl).With("rec", recommendation).With("au", authorId).With("dk", dedupeKey);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return (r.GetGuid(0), r.GetBoolean(1), r.Get<Guid?>("message_id"));
    }

    public async Task SetFindingMessageAsync(Guid findingId, Guid messageId, CancellationToken ct = default)
    {
        await using var cmd = db.Command("update ti_findings set message_id = @m where id = @id").With("m", messageId).With("id", findingId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<bool> UpdateFindingStatusAsync(Guid id, string status, CancellationToken ct = default)
    {
        await using var cmd = db.Command("update ti_findings set status = @s, updated_at = now() where id = @id").With("s", status).With("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    // ── posts and rate budgets ───────────────────────────────────────────────────────────────────
    /// <summary>Records that a board post for this hash has happened. False if it already had.</summary>
    public async Task<bool> ClaimPostAsync(string hash, string threadKey, CancellationToken ct = default)
    {
        await using var cmd = db.Command("insert into ti_posts (hash, thread_key) values (@h, @t) on conflict do nothing").With("h", hash).With("t", threadKey);
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task SetPostMessageAsync(string hash, Guid messageId, CancellationToken ct = default)
    {
        await using var cmd = db.Command("update ti_posts set message_id = @m where hash = @h").With("m", messageId).With("h", hash);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<Guid?> ThreadRootAsync(string threadKey, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            select p.message_id from ti_posts p join messages m on m.id = p.message_id
            where p.thread_key = @t and m.parent_id is null order by p.created_at limit 1
            """).With("t", threadKey);
        return await cmd.ExecuteScalarAsync(ct) as Guid?;
    }

    /// <summary>
    /// Takes one request from a shared budget (limit per rolling window), across every instance. Returns null when
    /// allowed, or how long until a slot frees up.
    /// </summary>
    public async Task<TimeSpan?> TryTakeAsync(string bucket, int limit, TimeSpan window, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await using (var lk = new NpgsqlCommand("select pg_advisory_xact_lock(7340020, hashtext(@b))", conn, tx).With("b", bucket))
            await lk.ExecuteNonQueryAsync(ct);
        await using (var del = new NpgsqlCommand("delete from ti_rate where bucket = @b and at < now() - @w", conn, tx).With("b", bucket).With("w", window))
            await del.ExecuteNonQueryAsync(ct);
        DateTimeOffset? oldest = null;
        int used;
        await using (var c = new NpgsqlCommand("select count(*)::int, min(at) from ti_rate where bucket = @b", conn, tx).With("b", bucket))
        await using (var r = await c.ExecuteReaderAsync(ct))
        {
            await r.ReadAsync(ct);
            used = r.GetInt32(0);
            if (!r.IsDBNull(1)) oldest = r.GetFieldValue<DateTimeOffset>(1);
        }
        if (used >= limit)
        {
            await tx.RollbackAsync(ct);
            var wait = oldest is { } o ? o + window - DateTimeOffset.UtcNow : window;
            return wait < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : wait;
        }
        await using (var ins = new NpgsqlCommand("insert into ti_rate (bucket) values (@b)", conn, tx).With("b", bucket))
            await ins.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
        return null;
    }

    private static string? Cap(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max];
}
