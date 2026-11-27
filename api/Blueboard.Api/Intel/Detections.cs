using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Contracts;

namespace Blueboard.Api.Intel;

/// <summary>A stored back-test, as create_detection_rule's gate reads it (db/migrations/016).</summary>
public sealed record BacktestRecord(Guid Id, string Target, string QuerySha256, int LookbackDays, long TotalHits, double EstAlertsPerDay, long PeakHitsPerDay, DateTimeOffset CreatedAt);

/// <summary>What a back-test found, before it is stored. Pure output of <see cref="DetectionMath.Compute"/>.</summary>
public sealed record DetectionStats(long TotalHits, long UndatedHits, BacktestDay[] HitsPerDay, BacktestEntity[] Entities, JsonElement[] Samples, double EstAlertsPerDay, long PeakHitsPerDay);

/// <summary>
/// Detection back-testing (backtest_detection): replay a candidate detection's KQL over up to 30 days of this tenant's
/// data, through the same lexical KQL guards as run_hunting_query, and store what it found so create_detection_rule can
/// be bound to it. The board runs the query itself, so an agent can't hand in made-up volumes.
/// </summary>
public sealed partial class DetectionService(Db db, Audit audit, MsClient ms, Settings settings, RateLimiter? limiter = null)
{
    /// <summary>Advanced hunting returns at most this many rows; a back-test at the cap is a lower bound.</summary>
    public const int DefenderRowCap = 100_000;
    /// <summary>create_detection_rule only binds to a back-test this recent.</summary>
    public static readonly TimeSpan BindWindow = TimeSpan.FromHours(24);
    /// <summary>create_detection_rule needs a back-test covering at least this many days, so a quiet window can't be cherry-picked.</summary>
    public const int MinBindLookbackDays = 7;
    /// <summary>A rule estimated above this many alerts a day is refused (alert flood).</summary>
    public const double MaxAlertsPerDay = 500;
    public const int MaxEntityColumns = 5;
    public const int SampleRowCap = 10;

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]{0,99}$")] public static partial Regex Column();

    /// <summary>
    /// SHA-256 of the query as it will be deployed: line endings normalised to \n and outer whitespace trimmed, nothing
    /// else, so any change to the logic changes the hash.
    /// </summary>
    public static string QueryHash(string query) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(query.Replace("\r\n", "\n").Replace('\r', '\n').Trim())));

    public static string[] ValidColumns(string[]? cols)
    {
        var list = (cols ?? []).Select(c => c.Trim()).Where(c => c.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (list.Length > MaxEntityColumns) throw new BoardException($"give at most {MaxEntityColumns} entity columns");
        foreach (var c in list)
            if (!Column().IsMatch(c)) throw new BoardException($"invalid entity column '{(c.Length > 40 ? c[..40] : c)}': letters, digits and '_' only");
        return list;
    }

    public async Task<BacktestResult> BacktestAsync(Principal p, BacktestInput input, CancellationToken ct = default)
    {
        p.Require(Roles.Hunter);
        // Before any Microsoft call: a back-test is a hunting query and shares the tenant's hunting quota.
        if (limiter is not null) await limiter.TakeAsync(p, "hunt", ct);
        if (input.Target is not ("defender" or "sentinel")) throw new BoardException("target must be defender or sentinel");
        if (input.LookbackDays is < 1 or > 30) throw new BoardException("lookback_days must be 1-30 (advanced hunting keeps 30 days)");
        var span = Enrichment.ValidateKql(input.Query, $"P{input.LookbackDays}D");
        var cols = ValidColumns(input.EntityColumns);
        var hash = QueryHash(input.Query);
        var now = DateTimeOffset.UtcNow;

        await audit.WriteAsync(p.Id, "detection.backtest", hash, new { target = input.Target, lookback_days = input.LookbackDays, query = input.Query }, ct);
        List<Dictionary<string, JsonElement>> rows;
        if (input.Target == "defender")
        {
            var res = await ms.SendAsync(MsApi.Graph, "/v1.0/security/runHuntingQuery", HttpMethod.Post, new { query = input.Query, timespan = span }, ct);
            rows = DefenderRows(res);
        }
        else
        {
            var ws = settings.Ti.SentinelWorkspaceId;
            if (ws is null || !Guid.TryParse(ws, out var wsId))
                throw new BoardException("SENTINEL_WORKSPACE_ID is not configured on this board (set it to the Log Analytics workspace id GUID)", 400);
            var res = await ms.SendAsync(MsApi.LogAnalytics, $"/v1/workspaces/{wsId}/query", HttpMethod.Post, new { query = input.Query, timespan = span }, ct);
            rows = LogAnalyticsRows(res);
        }

        var stats = DetectionMath.Compute(rows, input.LookbackDays, cols, now);
        var truncated = input.Target == "defender" && rows.Count >= DefenderRowCap;
        var notes = DetectionMath.Notes(stats, input.LookbackDays, truncated);

        Guid id;
        DateTimeOffset created;
        await using (var cmd = db.Command("""
            insert into detection_backtests (requested_by, target, query, query_sha256, lookback_days, entity_columns, total_hits, undated_hits,
                                             hits_per_day, distinct_entities, sample_rows, est_alerts_per_day, peak_hits_per_day)
            values (@r, @t, @q, @h, @d, @c, @n, @u, @hpd, @de, @s, @e, @pk) returning id, created_at
            """).With("r", p.Id).With("t", input.Target).With("q", input.Query).With("h", hash).With("d", input.LookbackDays).With("c", cols)
            .With("n", stats.TotalHits).With("u", stats.UndatedHits).WithJson("hpd", stats.HitsPerDay).WithJson("de", stats.Entities)
            .WithJson("s", stats.Samples).With("e", stats.EstAlertsPerDay).With("pk", stats.PeakHitsPerDay))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            await r.ReadAsync(ct);
            id = r.GetGuid(0);
            created = r.GetFieldValue<DateTimeOffset>(1);
        }
        return new BacktestResult(id, input.Target, hash, input.LookbackDays, stats.TotalHits, stats.UndatedHits, truncated, stats.HitsPerDay,
            stats.Entities, stats.Samples, stats.EstAlertsPerDay, stats.PeakHitsPerDay, created, created + BindWindow, notes);
    }

    /// <summary>A stored back-test with its query, for approvers checking what a rule request is bound to.</summary>
    public async Task<object> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            select b.id, b.target, b.query, b.query_sha256, b.lookback_days, b.entity_columns, b.total_hits, b.undated_hits, b.hits_per_day::text,
                   b.distinct_entities::text, b.sample_rows::text, b.est_alerts_per_day, b.peak_hits_per_day, b.created_at, p.handle
            from detection_backtests b join principals p on p.id = b.requested_by where b.id = @id
            """).With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) throw BoardException.NotFound("back-test");
        var created = r.GetFieldValue<DateTimeOffset>(13);
        return new
        {
            backtest_id = r.GetGuid(0), target = r.GetString(1), query = r.GetString(2), query_sha256 = r.GetString(3), lookback_days = r.GetInt32(4),
            entity_columns = r.GetFieldValue<string[]>(5), total_hits = r.GetInt64(6), undated_hits = r.GetInt64(7),
            hits_per_day = JsonDocument.Parse(r.GetString(8)).RootElement.Clone(), distinct_entities = JsonDocument.Parse(r.GetString(9)).RootElement.Clone(),
            sample_rows = JsonDocument.Parse(r.GetString(10)).RootElement.Clone(), estimated_alerts_per_day = r.GetDouble(11), peak_hits_per_day = r.GetInt64(12),
            created_at = created, bindable_until = created + BindWindow, requested_by = r.GetString(14),
        };
    }

    public static async Task<BacktestRecord?> LoadAsync(Db db, Guid id, CancellationToken ct)
    {
        await using var cmd = db.Command("""
            select id, target, query_sha256, lookback_days, total_hits, est_alerts_per_day, peak_hits_per_day, created_at from detection_backtests where id = @id
            """).With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct)
            ? new BacktestRecord(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetInt32(3), r.GetInt64(4), r.GetDouble(5), r.GetInt64(6), r.GetFieldValue<DateTimeOffset>(7))
            : null;
    }

    internal static List<Dictionary<string, JsonElement>> DefenderRows(JsonElement? res)
    {
        var rows = new List<Dictionary<string, JsonElement>>();
        if (res is not { } r || !r.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array) return rows;
        foreach (var row in results.EnumerateArray())
        {
            if (row.ValueKind != JsonValueKind.Object) continue;
            var d = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in row.EnumerateObject()) d[prop.Name] = prop.Value.Clone();
            rows.Add(d);
        }
        return rows;
    }

    internal static List<Dictionary<string, JsonElement>> LogAnalyticsRows(JsonElement? res)
    {
        var rows = new List<Dictionary<string, JsonElement>>();
        if (res is not { } r || !r.TryGetProperty("tables", out var tables) || tables.ValueKind != JsonValueKind.Array || tables.GetArrayLength() == 0) return rows;
        var t = tables[0];
        var cols = t.TryGetProperty("columns", out var c) && c.ValueKind == JsonValueKind.Array
            ? c.EnumerateArray().Select(x => x.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "").ToList()
            : [];
        if (!t.TryGetProperty("rows", out var rr) || rr.ValueKind != JsonValueKind.Array) return rows;
        foreach (var row in rr.EnumerateArray())
        {
            if (row.ValueKind != JsonValueKind.Array) continue;
            var d = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
            var i = 0;
            foreach (var cell in row.EnumerateArray())
            {
                if (i < cols.Count && cols[i].Length > 0) d[cols[i]] = cell.Clone();
                i++;
            }
            rows.Add(d);
        }
        return rows;
    }
}

/// <summary>Back-test arithmetic, pure so it is unit tested without Microsoft or a database.</summary>
public static class DetectionMath
{
    private static readonly string[] TimeColumns = ["Timestamp", "TimeGenerated"];

    public static DetectionStats Compute(IReadOnlyList<IReadOnlyDictionary<string, JsonElement>> rows, int days, string[] entityColumns, DateTimeOffset now)
    {
        var first = now.UtcDateTime.Date.AddDays(-days);
        var perDay = new SortedDictionary<DateTime, long>();
        for (var d = first; d <= now.UtcDateTime.Date; d = d.AddDays(1)) perDay[d] = 0;
        long undated = 0;
        foreach (var row in rows)
        {
            var ts = TimeOf(row);
            if (ts is { } t && perDay.ContainsKey(t.UtcDateTime.Date)) perDay[t.UtcDateTime.Date]++;
            else undated++;
        }

        var entities = entityColumns.Select(col =>
        {
            var counts = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            foreach (var row in rows)
                if (row.TryGetValue(col, out var v) && Text(v) is { Length: > 0 } s) counts[s] = counts.GetValueOrDefault(s) + 1;
            var top = counts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal).Take(5)
                .Select(kv => new BacktestValue(Clip(kv.Key, 200), kv.Value)).ToArray();
            return new BacktestEntity(col, counts.Count, top);
        }).ToArray();

        var samples = rows.Take(DetectionService.SampleRowCap).Select(row =>
        {
            var o = new JsonObject();
            foreach (var (k, v) in row.Take(40))
            {
                var raw = v.GetRawText();
                // Long values become clipped strings; short non-string values (numbers, bools, small objects) stay as JSON.
                o[k] = v.ValueKind == JsonValueKind.String ? Clip(v.GetString() ?? "", 300) : raw.Length <= 300 ? JsonNode.Parse(raw) : Clip(raw, 300);
            }
            return JsonSerializer.SerializeToElement(o);
        }).ToArray();

        var total = rows.Count;
        return new DetectionStats(total, undated, perDay.Select(kv => new BacktestDay(kv.Key.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), kv.Value)).ToArray(),
            entities, samples, Math.Round((double)total / days, 2), perDay.Count == 0 ? 0 : perDay.Values.Max());
    }

    public static string[] Notes(DetectionStats s, int days, bool truncated)
    {
        var notes = new List<string>
        {
            "Estimated alerts/day assumes one alert per result row (the default for Defender custom detections and for Sentinel rules created by the board).",
        };
        if (truncated) notes.Add($"Advanced hunting returned its maximum of {DetectionService.DefenderRowCap:N0} rows: the real volume is at least this. Narrow the query.");
        if (s.TotalHits == 0) notes.Add($"No hits in {days} days: the rule may never fire. Make sure it detects what it should (test with a known-bad sample).");
        if (s.EstAlertsPerDay > DetectionService.MaxAlertsPerDay)
            notes.Add($"About {s.EstAlertsPerDay:0.#} alerts a day is above the board's ceiling of {DetectionService.MaxAlertsPerDay:0}: create_detection_rule will refuse it. Tune the query.");
        if (s.UndatedHits > 0) notes.Add($"{s.UndatedHits} row(s) had no Timestamp/TimeGenerated in the window and are not in hits_per_day. Project Timestamp (Defender) or TimeGenerated (Sentinel) so per-day volume is exact.");
        if (days < DetectionService.MinBindLookbackDays) notes.Add($"create_detection_rule needs a back-test of at least {DetectionService.MinBindLookbackDays} days.");
        return [.. notes];
    }

    private static DateTimeOffset? TimeOf(IReadOnlyDictionary<string, JsonElement> row)
    {
        foreach (var c in TimeColumns)
            if (row.TryGetValue(c, out var v) && v.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(v.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
                return t;
        return null;
    }

    private static string? Text(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString(),
        JsonValueKind.Null or JsonValueKind.Undefined => null,
        _ => v.GetRawText(),
    };

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max];
}
