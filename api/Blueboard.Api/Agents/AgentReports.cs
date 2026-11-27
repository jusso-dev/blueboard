using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Agents;

public sealed record AgentDaySpend(string Handle, DateOnly Day, double LlmUsd, double MeteredUsd, long Tokens, int Calls);
public sealed record IncidentSpend(Guid Id, string GraphId, string DisplayName, string Status, string? Classification, double Usd, long Tokens, int Calls);
public sealed record AgentSpendRow(
    string Handle, string DisplayName, double Usd, long Tokens, int Reports, int Calls, int Verdicts, int ClosedIncidents,
    double? UsdPerVerdict, double? UsdPerClosedIncident, double MonthUsd, double ForecastMonthUsd, double? MonthlyUsdLimit,
    bool Unreported, string? UnpricedModel);
public sealed record AgentCostReport(
    object Range, double TotalUsd, long TotalTokens, double? UsdPerClosedIncident, double? UsdPerVerdict,
    double MonthToDateUsd, double ForecastMonthUsd, IReadOnlyList<AgentSpendRow> Agents, IReadOnlyList<AgentDaySpend> Daily,
    IReadOnlyList<IncidentSpend> Incidents, IReadOnlyList<AgentAccuracy> Accuracy);

/// <summary>
/// The agents dashboard (/agents, Board.Admin): spend per agent and day, per incident, cost per closed incident and per
/// verdict, month-to-date with a straight-line forecast to month end, budget burn, agents that call tools but never
/// report usage, and accuracy (feedback and overturns). Spend = agent-reported LLM cost priced by the board + board-side
/// metered tool cost.
/// </summary>
public sealed class AgentReports(Db db, AgentFeedback feedback)
{
    public async Task<AgentCostReport> BuildAsync(Principal me, DateTimeOffset? fromIn, DateTimeOffset? toIn, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        var to = toIn ?? DateTimeOffset.UtcNow;
        var from = fromIn ?? to.AddDays(-30);
        if (from >= to) throw new BoardException("from must be before to");
        if (to - from > TimeSpan.FromDays(400)) throw new BoardException("range must be at most 400 days");

        var daily = new List<AgentDaySpend>();
        await using (var cmd = db.Command("""
            with u as (select principal_id, (created_at at time zone 'utc')::date as day, sum(cost_usd) as usd,
                              sum(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens) as tokens
                       from agent_usage where created_at >= @from and created_at < @to group by 1, 2),
            m as (select principal_id, day, sum(cost_usd) as usd, sum(calls) as calls from agent_metered_daily
                  where day >= (@from at time zone 'utc')::date and day <= (@to at time zone 'utc')::date group by 1, 2)
            select p.handle, coalesce(u.day, m.day), coalesce(u.usd, 0), coalesce(m.usd, 0), coalesce(u.tokens, 0), coalesce(m.calls, 0)::int
            from u full join m on m.principal_id = u.principal_id and m.day = u.day
            join principals p on p.id = coalesce(u.principal_id, m.principal_id)
            where p.kind = 'agent'
            order by 2, 1
            """).With("from", from).With("to", to))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                daily.Add(new AgentDaySpend(r.GetString(0), DateOnly.FromDateTime(r.GetDateTime(1)), Math.Round((double)r.GetDecimal(2), 4),
                    Math.Round((double)r.GetDecimal(3), 4), (long)r.GetDecimal(4), r.GetInt32(5)));

        var incidents = new List<IncidentSpend>();
        await using (var cmd = db.Command("""
            with u as (select incident_id, sum(cost_usd) as usd, sum(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens) as tokens
                       from agent_usage where incident_id is not null and created_at >= @from and created_at < @to group by 1),
            c as (select incident_id, count(*)::int as calls from agent_tool_calls where incident_id is not null and created_at >= @from and created_at < @to group by 1)
            select i.id, i.graph_id, i.display_name, i.status, i.classification, coalesce(u.usd, 0), coalesce(u.tokens, 0), coalesce(c.calls, 0)
            from incidents i left join u on u.incident_id = i.id left join c on c.incident_id = i.id
            where u.incident_id is not null or c.incident_id is not null
            order by coalesce(u.usd, 0) desc, coalesce(c.calls, 0) desc limit 200
            """).With("from", from).With("to", to))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                incidents.Add(new IncidentSpend(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.Get<string>("classification"),
                    Math.Round((double)r.GetDecimal(5), 4), (long)r.GetDecimal(6), r.GetInt32(7)));

        var agents = new List<AgentSpendRow>();
        var now = DateTimeOffset.UtcNow;
        var monthStart = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var monthDays = DateTime.DaysInMonth(now.Year, now.Month);
        var elapsedDays = Math.Max((now - monthStart).TotalDays, 1d / 24);
        await using (var cmd = db.Command("""
            with month as (select date_trunc('month', now() at time zone 'utc')::date as m)
            select p.handle, p.display_name,
              coalesce((select sum(cost_usd) from agent_usage u where u.principal_id = p.id and u.created_at >= @from and u.created_at < @to), 0)
                + coalesce((select sum(cost_usd) from agent_metered_daily d where d.principal_id = p.id and d.day >= (@from at time zone 'utc')::date and d.day <= (@to at time zone 'utc')::date), 0),
              coalesce((select sum(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens) from agent_usage u where u.principal_id = p.id and u.created_at >= @from and u.created_at < @to), 0),
              (select count(*)::int from agent_usage u where u.principal_id = p.id and u.created_at >= @from and u.created_at < @to),
              coalesce((select sum(calls) from agent_metered_daily d where d.principal_id = p.id and d.day >= (@from at time zone 'utc')::date and d.day <= (@to at time zone 'utc')::date), 0)::int,
              (select count(*)::int from messages m where m.author_id = p.id and m.type = 'verdict' and m.created_at >= @from and m.created_at < @to),
              (select count(distinct i.id)::int from incidents i where i.status = 'resolved' and exists (
                 select 1 from messages m where m.incident_id = i.id and m.author_id = p.id and m.created_at >= @from and m.created_at < @to)),
              coalesce((select sum(cost_usd) from agent_usage u, month where u.principal_id = p.id and u.created_at >= month.m::timestamp at time zone 'utc'), 0)
                + coalesce((select sum(cost_usd) from agent_metered_daily d, month where d.principal_id = p.id and d.day >= month.m), 0),
              (select monthly_usd from agent_budgets b where b.principal_id = p.id),
              exists (select 1 from agent_metered_daily d where d.principal_id = p.id and d.day >= (@from at time zone 'utc')::date)
                and not exists (select 1 from agent_usage u where u.principal_id = p.id and u.created_at >= @from),
              (select model from agent_usage u where u.principal_id = p.id and u.cost_source = 'unpriced' and u.created_at >= @from order by u.id desc limit 1)
            from principals p where p.kind = 'agent'
              and (exists (select 1 from agent_usage u where u.principal_id = p.id and u.created_at >= @from)
                or exists (select 1 from agent_metered_daily d where d.principal_id = p.id and d.day >= (@from at time zone 'utc')::date))
            order by 3 desc, p.handle
            """).With("from", from).With("to", to))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
            {
                var usd = (double)r.GetDecimal(2);
                var verdicts = r.GetInt32(6);
                var closed = r.GetInt32(7);
                var month = (double)r.GetDecimal(8);
                agents.Add(new AgentSpendRow(r.GetString(0), r.GetString(1), Math.Round(usd, 4), (long)r.GetDecimal(3), r.GetInt32(4), r.GetInt32(5),
                    verdicts, closed, verdicts > 0 ? Math.Round(usd / verdicts, 4) : null, closed > 0 ? Math.Round(usd / closed, 4) : null,
                    Math.Round(month, 4), Math.Round(Forecast(month, elapsedDays, monthDays), 2),
                    r.IsDBNull(9) ? null : (double)r.GetDecimal(9), r.GetBoolean(10), r.Get<string>("model")));
            }

        var total = agents.Sum(a => a.Usd);
        var totalVerdicts = agents.Sum(a => a.Verdicts);
        int closedIncidents;
        await using (var cmd = db.Command("""
            select count(distinct i.id)::int from incidents i join messages m on m.incident_id = i.id join principals p on p.id = m.author_id
            where i.status = 'resolved' and p.kind = 'agent' and m.created_at >= @from and m.created_at < @to
            """).With("from", from).With("to", to))
            closedIncidents = (int)(await cmd.ExecuteScalarAsync(ct))!;
        var mtd = agents.Sum(a => a.MonthUsd);
        return new AgentCostReport(new { from, to }, Math.Round(total, 4), agents.Sum(a => a.Tokens),
            closedIncidents > 0 ? Math.Round(total / closedIncidents, 4) : null, totalVerdicts > 0 ? Math.Round(total / totalVerdicts, 4) : null,
            Math.Round(mtd, 4), Math.Round(Forecast(mtd, elapsedDays, monthDays), 2), agents, daily, incidents,
            await feedback.AccuracyAsync(from, to, ct));
    }

    /// <summary>Straight-line month-end forecast from month-to-date spend.</summary>
    public static double Forecast(double monthToDate, double elapsedDays, int daysInMonth) =>
        elapsedDays <= 0 ? monthToDate : monthToDate / elapsedDays * daysInMonth;
}
