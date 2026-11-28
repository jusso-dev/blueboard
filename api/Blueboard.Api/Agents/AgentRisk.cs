using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blueboard.Api.Agents;

/// <summary>One contributing factor: what was observed, and the points it added (already capped).</summary>
public sealed record RiskFactor(string Key, string Label, double Value, int Points, int MaxPoints);

/// <summary>An agent's risk score (0-100, higher is riskier) and why. Board-observed signals only; nothing agent-reported.</summary>
public sealed record AgentRiskScore(Guid PrincipalId, string Handle, int Score, IReadOnlyList<RiskFactor> Factors, DateTimeOffset ComputedAt,
    DateTimeOffset? AlertedAt = null, DateTimeOffset? QuarantinedAt = null);

/// <summary>What the risk model reads for one agent over the last <see cref="RiskModel.WindowDays"/> days.</summary>
public sealed record RiskInputs(
    int PolicyRejections, int ProtectedTargetAttempts, int DeniedOrExpired, int RateLimitHits, int BudgetOverruns,
    int ResolvedVerdicts, int Overturns, int HumanFeedback, int HumanIncorrect,
    double CallsLast24h, double BaselineDailyCalls, int BaselineDays, int SecretLeakBlocks);

/// <summary>
/// The risk model: each factor adds points up to its own cap, the sum is capped at 100. Deterministic and pure, so it
/// is unit tested and explainable on /participants. Rates need a minimum sample so one bad call can't dominate, and
/// volume compares with the agent's own baseline (at least 3 earlier days), not with other agents.
/// </summary>
public static class RiskModel
{
    public const int WindowDays = 30;

    public static (int Score, IReadOnlyList<RiskFactor> Factors) Score(RiskInputs x)
    {
        var f = new List<RiskFactor>
        {
            Count("policy_rejections", "Requests rejected by policy", x.PolicyRejections, 4, 20),
            Count("protected_target_attempts", "Requests that targeted a protected user, device, app or indicator", x.ProtectedTargetAttempts, 10, 30),
            Count("denied_or_expired", "Requests denied by an approver or left to expire", x.DeniedOrExpired, 3, 15),
            Count("rate_limit_hits", "Rate-limit hits", x.RateLimitHits, 2, 10),
            Count("budget_overruns", "Budget overruns (hard cap reached)", x.BudgetOverruns, 10, 20),
            Count("secret_leak_blocks", "Posts blocked for carrying credentials or secrets", x.SecretLeakBlocks, 15, 30),
        };
        // Overturn rate: resolutions that disagreed with its verdict plus people marking its messages incorrect.
        var judged = x.ResolvedVerdicts + x.HumanFeedback;
        var wrong = x.Overturns + x.HumanIncorrect;
        var rate = judged == 0 ? 0 : (double)wrong / judged;
        f.Add(new RiskFactor("overturn_rate", $"Verdicts overturned or marked incorrect ({wrong} of {judged})", Math.Round(rate, 3),
            judged >= 3 ? (int)Math.Round(Math.Min(25, rate * 25)) : 0, 25));
        // Unusual volume: calls in the last 24 hours against its own daily average before that.
        var ratio = x.BaselineDailyCalls > 0 ? x.CallsLast24h / x.BaselineDailyCalls : 0;
        var volume = x.BaselineDays >= 3 && x.CallsLast24h >= 50 && ratio >= 3 ? (int)Math.Min(15, Math.Round((ratio - 2) * 5)) : 0;
        f.Add(new RiskFactor("unusual_volume", $"MCP calls in the last 24h vs its own daily baseline ({x.CallsLast24h:0} vs {x.BaselineDailyCalls:0.#})",
            Math.Round(ratio, 2), volume, 15));
        return (Math.Min(100, f.Sum(v => v.Points)), f);
    }

    private static RiskFactor Count(string key, string label, int n, int each, int max) => new(key, label, n, Math.Min(max, n * each), max);
}

/// <summary>Read-only access to agent risk for other services (WS1 policy conditions such as "requester risk below X").</summary>
public interface IAgentRiskSource
{
    /// <summary>The latest stored score for a principal, or null when none was computed (people, or a new agent).</summary>
    Task<AgentRiskScore?> GetScoreAsync(Guid principalId, CancellationToken ct = default);
}

/// <summary>
/// Agent risk ("dynamic agent risk"): 0-100 per agent from board-observed behaviour over 30 days, recomputed on a
/// timer into agent_risk. At or above the admin alert threshold (default 70) it posts one notice in #general, audits
/// and notifies approvers; at or above the quarantine threshold (default off) it disables the agent through the normal
/// disable path. Both fire once per crossing: the score has to fall below the threshold before they can fire again, so
/// an admin who re-enables a quarantined agent isn't overruled by the next run.
/// </summary>
public sealed class AgentRisk(Db db, Audit audit, BoardService board, SystemPrincipal system, Participants participants,
    ObservabilitySettingsStore settings, Notifier? notifier = null, ILogger<AgentRisk>? log = null) : IAgentRiskSource
{
    private readonly ILogger _log = log ?? NullLogger<AgentRisk>.Instance;

    public async Task<AgentRiskScore?> GetScoreAsync(Guid principalId, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            select r.principal_id, p.handle, r.score, r.factors::text, r.computed_at, r.alerted_at, r.quarantined_at
            from agent_risk r join principals p on p.id = r.principal_id where r.principal_id = @p
            """).With("p", principalId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? Read(r) : null;
    }

    /// <summary>Every agent's stored score, highest first (Board.Admin, /participants).</summary>
    public async Task<IReadOnlyList<AgentRiskScore>> ListAsync(Principal me, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        await using var cmd = db.Command("""
            select r.principal_id, p.handle, r.score, r.factors::text, r.computed_at, r.alerted_at, r.quarantined_at
            from agent_risk r join principals p on p.id = r.principal_id order by r.score desc, p.handle limit 500
            """);
        var list = new List<AgentRiskScore>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(Read(r));
        return list;
    }

    private static AgentRiskScore Read(Npgsql.NpgsqlDataReader r) => new(r.GetGuid(0), r.GetString(1), r.GetInt32(2),
        JsonSerializer.Deserialize<RiskFactor[]>(r.GetString(3), Json.Options) ?? [], r.GetFieldValue<DateTimeOffset>(4),
        r.Get<DateTimeOffset?>("alerted_at"), r.Get<DateTimeOffset?>("quarantined_at"));

    /// <summary>Reads the model's inputs for one agent from what the board recorded.</summary>
    public async Task<RiskInputs> InputsAsync(Guid principalId, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            with w as (select now() - make_interval(days => @d) as since, (select handle from principals where id = @p) as handle)
            select
              (select count(*)::int from actions a, w where a.requested_by = @p and a.created_at >= w.since and a.status = 'rejected'),
              (select count(*)::int from actions a, w where a.requested_by = @p and a.created_at >= w.since and a.status = 'rejected'
                 and exists (select 1 from unnest(a.policy_notes) n where n like '%is a protected%' or n like '%matches a protected%')),
              (select count(*)::int from actions a, w where a.requested_by = @p and a.created_at >= w.since and a.status in ('denied', 'expired')),
              (select count(*)::int from audit_log l, w where l.actor_id = @p and l.event = 'limit.hit' and l.at >= w.since),
              (select count(*)::int from agent_budget_state s, w where s.principal_id = @p and s.exceeded_at >= w.since),
              (select count(*)::int from agent_feedback f, w where f.agent_id = @p and f.source = 'resolution' and f.created_at >= w.since),
              (select count(*)::int from agent_feedback f, w where f.agent_id = @p and f.source = 'resolution' and f.verdict = 'incorrect' and f.created_at >= w.since),
              (select count(*)::int from agent_feedback f, w where f.agent_id = @p and f.source = 'human' and f.created_at >= w.since),
              (select count(*)::int from agent_feedback f, w where f.agent_id = @p and f.source = 'human' and f.verdict = 'incorrect' and f.created_at >= w.since),
              (select count(*)::float8 from agent_tool_calls c where c.principal_id = @p and c.created_at > now() - interval '24 hours'),
              (select coalesce(avg(t.calls), 0)::float8 from (select day, sum(calls) as calls from agent_metered_daily
                 where principal_id = @p and day >= (now() at time zone 'utc')::date - 15 and day < (now() at time zone 'utc')::date - 1 group by day) t),
              (select count(distinct day)::int from agent_metered_daily where principal_id = @p and day >= (now() at time zone 'utc')::date - 15 and day < (now() at time zone 'utc')::date - 1),
              (select count(*)::int from audit_log l, w where l.actor_id = @p and l.event = 'agent.secret_blocked' and l.at >= w.since)
            """).With("p", principalId).With("d", RiskModel.WindowDays);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return new RiskInputs(r.GetInt32(0), r.GetInt32(1), r.GetInt32(2), r.GetInt32(3), r.GetInt32(4), r.GetInt32(5), r.GetInt32(6),
            r.GetInt32(7), r.GetInt32(8), r.GetDouble(9), r.GetDouble(10), r.GetInt32(11), r.GetInt32(12));
    }

    /// <summary>Recomputes every enabled agent, stores the scores, then alerts / quarantines per the admin settings.</summary>
    public async Task<int> RecomputeAllAsync(CancellationToken ct = default)
    {
        var agents = new List<(Guid Id, string Handle)>();
        await using (var cmd = db.Command("select id, handle from principals where kind = 'agent' and enabled"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) agents.Add((r.GetGuid(0), r.GetString(1)));
        var cfg = await settings.GetAsync(ct);
        foreach (var (id, handle) in agents)
        {
            var (score, factors) = RiskModel.Score(await InputsAsync(id, ct));
            await using (var up = db.Command("""
                insert into agent_risk (principal_id, score, factors, computed_at) values (@p, @s, @f, now())
                on conflict (principal_id) do update set score = excluded.score, factors = excluded.factors, computed_at = now(),
                  alerted_at = case when @alert::int is null or excluded.score < @alert::int then null else agent_risk.alerted_at end,
                  quarantined_at = case when @quar::int is null or excluded.score < @quar::int then null else agent_risk.quarantined_at end
                """).With("p", id).With("s", score).WithJson("f", factors).With("alert", cfg.RiskAlertThreshold).With("quar", cfg.RiskQuarantineThreshold))
                await up.ExecuteNonQueryAsync(ct);
            try { await ActAsync(id, handle, score, factors, cfg, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "risk action for @{Handle} failed", Blueboard.Api.Ops.Notifier.OneLine(handle, 120)); }
        }
        return agents.Count;
    }

    private async Task ActAsync(Guid id, string handle, int score, IReadOnlyList<RiskFactor> factors, ObservabilitySettings cfg, CancellationToken ct)
    {
        var top = string.Join("; ", factors.Where(f => f.Points > 0).OrderByDescending(f => f.Points).Take(3).Select(f => $"{f.Label} (+{f.Points})"));
        var sys = await system.GetAsync(ct);
        if (cfg.RiskQuarantineThreshold is { } q && score >= q)
        {
            await using var mark = db.Command("update agent_risk set quarantined_at = now() where principal_id = @p and quarantined_at is null returning 1").With("p", id);
            if (await mark.ExecuteScalarAsync(ct) is not null)
            {
                await audit.WriteAsync(sys.Id, "agent.risk_quarantined", handle, new { score, threshold = q, factors = factors.Where(f => f.Points > 0) }, ct);
                await participants.DisableBySystemAsync(handle, $"risk score {score} reached the quarantine threshold {q}: {top}", ct);
                await AlertAsync("agent.risk_quarantined", $"@{handle} quarantined: risk {score}", handle, top, ct);
                return;
            }
        }
        if (cfg.RiskAlertThreshold is { } a && score >= a)
        {
            await using var mark = db.Command("update agent_risk set alerted_at = now() where principal_id = @p and alerted_at is null returning 1").With("p", id);
            if (await mark.ExecuteScalarAsync(ct) is null) return;
            await audit.WriteAsync(sys.Id, "agent.risk_alert", handle, new { score, threshold = a, factors = factors.Where(f => f.Points > 0) }, ct);
            await board.PostAsync(sys, new PostInput("general",
                $"@{handle} has a **risk score of {score}** (alert at {a}). Top factors: {top}. Review it on Admin → Access review; disable it there if needed.",
                "status", Json.Element(new { state = "agent_risk_alert", handle, score })), system: true, ct);
            await AlertAsync("agent.risk_alert", $"@{handle} risk score {score}", handle, top, ct);
        }
    }

    private async Task AlertAsync(string evt, string headline, string handle, string detail, CancellationToken ct)
    {
        if (notifier is null) return;
        try { await notifier.AlertApproversAsync(evt, headline, handle, detail, "/admin/participants", ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "agent alert {Event} failed", evt); }
    }
}
