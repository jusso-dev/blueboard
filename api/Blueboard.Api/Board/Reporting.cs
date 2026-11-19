using System.Text;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Board;

public sealed record Stat(double? Median, double? P90, int N);
public sealed record IncidentTiming(Guid Id, string GraphId, string DisplayName, string Severity, string Status, DateTimeOffset FirstSeenAt,
    double? EnrichmentS, double? VerdictS, double? ContainmentS, int Messages, int Actions);
public sealed record Coverage(int Total, int Enriched, int WithVerdict, int Contained);
public sealed record OutcomeCount(string Status, int N);
public sealed record Report(object Range, Coverage Incidents, Stat Enrichment, Stat Verdict, Stat Containment, Stat Approval,
    IReadOnlyList<OutcomeCount> Actions, IReadOnlyList<IncidentTiming> Rows);

/// <summary>Response metrics from when the board first saw each incident. Durations in seconds.</summary>
public sealed class Reporting(Db db)
{
    private static readonly string[] ContainKinds = ["isolate_device", "disable_user", "revoke_sessions", "block_indicator"];

    public async Task<Report> BuildAsync(DateTimeOffset? fromIn, DateTimeOffset? toIn, string? severity, CancellationToken ct = default)
    {
        var to = toIn ?? DateTimeOffset.UtcNow;
        var from = fromIn ?? to.AddDays(-30);
        if (from >= to) throw new BoardException("from must be before to");
        if (severity is { Length: > 20 }) throw new BoardException("invalid severity");

        var rows = new List<IncidentTiming>();
        await using (var cmd = db.Command($"""
            with inc as (
              select i.id, i.graph_id, i.display_name, i.severity, i.status, i.first_seen_at
              from incidents i
              where i.first_seen_at >= @from and i.first_seen_at < @to {(severity is null ? "" : "and lower(i.severity) = lower(@sev)")}
            )
            select inc.id, inc.graph_id, inc.display_name, inc.severity, inc.status, inc.first_seen_at,
              extract(epoch from (select min(m.created_at) from messages m join principals p on p.id = m.author_id
                where m.incident_id = inc.id and m.type in ('finding','ioc','verdict') and p.kind <> 'system') - inc.first_seen_at)::float8,
              extract(epoch from (select min(m.created_at) from messages m where m.incident_id = inc.id and m.type = 'verdict') - inc.first_seen_at)::float8,
              extract(epoch from (select min(a.updated_at) from actions a where a.incident_id = inc.id and a.status = 'succeeded' and a.kind = any(@ck)) - inc.first_seen_at)::float8,
              (select count(*)::int from messages m where m.incident_id = inc.id),
              (select count(*)::int from actions a where a.incident_id = inc.id)
            from inc order by inc.first_seen_at desc limit 500
            """).With("from", from).With("to", to).With("sev", severity).With("ck", ContainKinds))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                rows.Add(new IncidentTiming(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetFieldValue<DateTimeOffset>(5),
                    r.IsDBNull(6) ? null : r.GetDouble(6), r.IsDBNull(7) ? null : r.GetDouble(7), r.IsDBNull(8) ? null : r.GetDouble(8), r.GetInt32(9), r.GetInt32(10)));

        Stat approval;
        await using (var cmd = db.Command("""
            select percentile_cont(0.5) within group (order by s)::float8, percentile_cont(0.9) within group (order by s)::float8, count(*)::int
            from (select extract(epoch from (a.decided_at - a.created_at)) as s from actions a
                  where a.requires_approval and a.decided_at is not null and a.created_at >= @from and a.created_at < @to) t
            """).With("from", from).With("to", to))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            await r.ReadAsync(ct);
            approval = new Stat(r.IsDBNull(0) ? null : r.GetDouble(0), r.IsDBNull(1) ? null : r.GetDouble(1), r.GetInt32(2));
        }

        var outcomes = new List<OutcomeCount>();
        await using (var cmd = db.Command("select status, count(*)::int from actions where created_at >= @from and created_at < @to group by status order by 2 desc")
                         .With("from", from).With("to", to))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) outcomes.Add(new OutcomeCount(r.GetString(0), r.GetInt32(1)));

        Stat StatOf(Func<IncidentTiming, double?> sel)
        {
            var xs = rows.Select(sel).OfType<double>().Where(v => v >= 0).ToList();
            return new Stat(Percentile(xs, 0.5), Percentile(xs, 0.9), xs.Count);
        }

        return new Report(
            new { from, to },
            new Coverage(rows.Count, rows.Count(r => r.EnrichmentS is not null), rows.Count(r => r.VerdictS is not null), rows.Count(r => r.ContainmentS is not null)),
            StatOf(r => r.EnrichmentS), StatOf(r => r.VerdictS), StatOf(r => r.ContainmentS), approval, outcomes, rows);
    }

    /// <summary>Linear interpolation, same method as Postgres percentile_cont.</summary>
    public static double? Percentile(IReadOnlyList<double> values, double p)
    {
        if (values.Count == 0) return null;
        var xs = values.Order().ToArray();
        var idx = (xs.Length - 1) * p;
        var lo = (int)Math.Floor(idx);
        var hi = (int)Math.Ceiling(idx);
        return xs[lo] + (xs[hi] - xs[lo]) * (idx - lo);
    }

    public static string Csv(Report r)
    {
        static string Esc(object? v)
        {
            if (v is null) return "";
            var s = Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "";
            if (s.Length > 0 && "=+-@\t\r".Contains(s[0])) s = "'" + s; // formula injection guard
            return s.IndexOfAny([',', '"', '\n']) >= 0 ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
        }
        static object? Round(double? v) => v is null ? null : Math.Round(v.Value);
        var sb = new StringBuilder("incident,name,severity,status,first_seen_at,enrichment_s,verdict_s,containment_s,messages,actions\n");
        foreach (var x in r.Rows)
            sb.AppendJoin(',', new[] { x.GraphId, x.DisplayName, x.Severity, x.Status, x.FirstSeenAt.UtcDateTime.ToString("O"), Round(x.EnrichmentS), Round(x.VerdictS), Round(x.ContainmentS), x.Messages, (object)x.Actions }.Select(Esc)).Append('\n');
        return sb.ToString();
    }
}
