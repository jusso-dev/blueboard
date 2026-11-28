using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Blueboard.Api.Agents;

/// <summary>An agent's budget as an admin sees it, with its spend this UTC day and month and any active top-ups.</summary>
public sealed record AgentBudgetRow(
    Guid PrincipalId, string Handle, string DisplayName, bool Enabled,
    double? DailyUsd, double? MonthlyUsd, long? DailyTokens, long? MonthlyTokens, int SoftPct, string? Note,
    string? UpdatedBy, DateTimeOffset? UpdatedAt,
    double DayUsd, long DayTokens, double MonthUsd, long MonthTokens, double TopupUsd, long TopupTokens,
    bool Blocked, string? BlockedReason, DateTimeOffset? LastReportAt, int CallsWithoutReport7d);

/// <summary>
/// Agent LLM usage (report_usage) and hard budgets. Agents report what each model call used; the board prices it from
/// its own price table and adds board-side metered tool costs. Budgets, top-ups and limits are human-only (Board.Admin)
/// and never reachable over MCP. When an agent goes over a limit the board blocks its MCP calls (except whoami,
/// report_usage and releasing a claim), releases its open claims, posts one notice in #general, audits it and alerts
/// approvers. A daily block lifts at the next UTC day, a monthly one at the next month, or when an admin raises the
/// budget or grants a top-up.
/// </summary>
public sealed class AgentBudgets(Db db, Audit audit, BoardService board, SystemPrincipal system, PriceTable prices, Notifier? notifier = null, ILogger<AgentBudgets>? log = null)
{
    private readonly ILogger _log = log ?? NullLogger<AgentBudgets>.Instance;

    /// <summary>MCP tools an over-budget agent may still call. complete_claim only with outcome=release.</summary>
    public static readonly HashSet<string> AllowedWhenBlocked = [Tools.WhoAmI, Tools.ReportUsage, Tools.CompleteClaim];

    // ── usage ─────────────────────────────────────────────────────────────────────────────────────

    public async Task<UsageReceipt> ReportAsync(Principal me, UsageReportInput u, CancellationToken ct = default)
    {
        if (me.Kind != "agent") throw BoardException.Forbidden("only agents report LLM usage");
        // Contract ranges already hold; re-check what an attacker could still send through a custom client.
        long[] counts = [u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens];
        if (counts.Any(c => c is < 0 or > 50_000_000)) throw new BoardException("token counts must be 0–50,000,000");
        if (counts.Sum() == 0) throw new BoardException("report at least one token");
        if (u.CostUsd is < 0 or > 1000 || u.CostUsd is { } cu && (double.IsNaN(cu) || double.IsInfinity(cu))) throw new BoardException("cost_usd must be 0–1000");
        var model = u.Model.Trim();
        if (model.Length is 0 or > 100) throw new BoardException("model must be 1–100 characters");

        var price = prices.For(model);
        var (cost, source) = price is not null
            ? (price.Cost(u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens), "price_table")
            : u.CostUsd is { } c ? (c, "agent") : (0d, "unpriced");
        var incidentId = await board.ResolveIncidentAsync(u.Incident, ct);
        // Linked ids must exist; a dangling id is dropped rather than failing the report.
        Guid? message = u.MessageId is { } mid && await ExistsAsync(mid, ct) ? mid : null;
        Guid? claim = u.ClaimMessageId is { } cid && await ExistsAsync(cid, ct) ? cid : null;
        if (incidentId is null && (claim ?? message) is { } linked) incidentId = await IncidentOfAsync(linked, ct);

        long id;
        var duplicate = false;
        await using (var cmd = db.Command("""
            insert into agent_usage (principal_id, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
                                     cost_usd, cost_source, agent_cost_usd, request_id, message_id, claim_message_id, incident_id)
            values (@p, @m, @i, @o, @cr, @cw, @c, @s, @ac, @r, @msg, @claim, @inc)
            on conflict (principal_id, request_id) where request_id is not null do nothing
            returning id
            """).With("p", me.Id).With("m", model).With("i", u.InputTokens).With("o", u.OutputTokens).With("cr", u.CacheReadTokens)
                .With("cw", u.CacheWriteTokens).With("c", (decimal)Math.Round(cost, 6)).With("s", source).With("ac", u.CostUsd is { } a ? (decimal)a : null)
                .With("r", u.RequestId).With("msg", message).With("claim", claim).With("inc", incidentId))
        {
            if (await cmd.ExecuteScalarAsync(ct) is long newId) id = newId;
            else
            {
                duplicate = true;
                await using var ex = db.Command("select id from agent_usage where principal_id = @p and request_id = @r").With("p", me.Id).With("r", u.RequestId);
                id = (long)(await ex.ExecuteScalarAsync(ct))!;
            }
        }
        var position = await EvaluateAsync(me.Id, ct);
        return new UsageReceipt(id, model, counts.Sum(), Math.Round(cost, 6), source, duplicate, position);
    }

    private async Task<bool> ExistsAsync(Guid messageId, CancellationToken ct)
    {
        await using var cmd = db.Command("select 1 from messages where id = @id").With("id", messageId);
        return await cmd.ExecuteScalarAsync(ct) is not null;
    }

    private async Task<Guid?> IncidentOfAsync(Guid messageId, CancellationToken ct)
    {
        await using var cmd = db.Command("select incident_id from messages where id = @id").With("id", messageId);
        return await cmd.ExecuteScalarAsync(ct) as Guid?;
    }

    // ── metering (board side) ─────────────────────────────────────────────────────────────────────

    /// <summary>Counts one MCP call against the principal's daily metered totals (and its configured per-call price).</summary>
    public async Task MeterAsync(Guid principalId, string tool, bool error, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            insert into agent_metered_daily as d (principal_id, day, tool, calls, errors, cost_usd)
            values (@p, (now() at time zone 'utc')::date, @t, 1, @e, @c)
            on conflict (principal_id, day, tool) do update
              set calls = d.calls + 1, errors = d.errors + excluded.errors, cost_usd = d.cost_usd + excluded.cost_usd
            """).With("p", principalId).With("t", tool).With("e", error ? 1 : 0).With("c", (decimal)prices.ToolPrice(tool));
        await cmd.ExecuteNonQueryAsync(ct);
        // A priced tool call is spend: re-check the budget so metered cost alone can trip the cap.
        if (prices.ToolPrice(tool) > 0) await EvaluateAsync(principalId, ct);
    }

    // ── enforcement ───────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The hard cap. Throws 402-style BoardException (status 429 is rate limiting; budget uses 402 Payment Required)
    /// when the agent is over budget and the tool isn't one it may still call. Cheap: one indexed lookup.
    /// </summary>
    public async Task EnforceAsync(Principal me, string tool, string? completeOutcome, CancellationToken ct = default)
    {
        if (me.Kind != "agent") return;
        if (tool == Tools.WhoAmI || tool == Tools.ReportUsage) return;
        if (tool == Tools.CompleteClaim && completeOutcome == "release") return;
        await using var cmd = db.Command("""
            select period, detail->>'reason' from agent_budget_state
            where principal_id = @p and exceeded_at is not null and cleared_at is null
              and ((period = 'day' and period_start = (now() at time zone 'utc')::date)
                or (period = 'month' and period_start = date_trunc('month', now() at time zone 'utc')::date))
            limit 1
            """).With("p", me.Id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return;
        var period = r.GetString(0);
        var reason = r.IsDBNull(1) ? "budget exceeded" : r.GetString(1);
        throw new BoardException(
            $"budget exceeded: {reason}. Your MCP calls are refused until the {(period == "day" ? "next UTC day" : "next UTC month")} or an admin raises your budget; you may still call whoami, report_usage and complete_claim with outcome=release",
            402) { Bucket = "budget" };
    }

    /// <summary>Spend for the current UTC day and month: reported LLM cost plus metered tool cost; tokens are reported only.</summary>
    private static async Task<(double DayUsd, long DayTokens, double MonthUsd, long MonthTokens)> SpendAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Guid principalId, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            with b as (select (now() at time zone 'utc')::date as d0, date_trunc('month', now() at time zone 'utc')::date as m0)
            select
              coalesce((select sum(u.cost_usd) from agent_usage u, b where u.principal_id = @p and u.created_at >= b.d0::timestamp at time zone 'utc'), 0)
                + coalesce((select sum(m.cost_usd) from agent_metered_daily m, b where m.principal_id = @p and m.day = b.d0), 0),
              coalesce((select sum(u.input_tokens + u.output_tokens + u.cache_read_tokens + u.cache_write_tokens) from agent_usage u, b where u.principal_id = @p and u.created_at >= b.d0::timestamp at time zone 'utc'), 0),
              coalesce((select sum(u.cost_usd) from agent_usage u, b where u.principal_id = @p and u.created_at >= b.m0::timestamp at time zone 'utc'), 0)
                + coalesce((select sum(m.cost_usd) from agent_metered_daily m, b where m.principal_id = @p and m.day >= b.m0), 0),
              coalesce((select sum(u.input_tokens + u.output_tokens + u.cache_read_tokens + u.cache_write_tokens) from agent_usage u, b where u.principal_id = @p and u.created_at >= b.m0::timestamp at time zone 'utc'), 0)
            """, conn, tx).With("p", principalId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return ((double)r.GetDecimal(0), (long)r.GetDecimal(1), (double)r.GetDecimal(2), (long)r.GetDecimal(3));
    }

    private sealed record Limits(double? DailyUsd, double? MonthlyUsd, long? DailyTokens, long? MonthlyTokens, int SoftPct, double TopupUsd, long TopupTokens);

    private static async Task<Limits?> LimitsAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Guid principalId, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            select b.daily_usd, b.monthly_usd, b.daily_tokens, b.monthly_tokens, b.soft_pct,
                   coalesce((select sum(usd) from agent_budget_topups t where t.principal_id = b.principal_id and t.expires_at > now()), 0),
                   coalesce((select sum(tokens) from agent_budget_topups t where t.principal_id = b.principal_id and t.expires_at > now()), 0)
            from agent_budgets b where b.principal_id = @p
            """, conn, tx).With("p", principalId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return null;
        return new Limits(r.IsDBNull(0) ? null : (double)r.GetDecimal(0), r.IsDBNull(1) ? null : (double)r.GetDecimal(1),
            r.IsDBNull(2) ? null : r.GetInt64(2), r.IsDBNull(3) ? null : r.GetInt64(3), r.GetInt32(4),
            (double)r.GetDecimal(5), (long)r.GetDecimal(6));
    }

    /// <summary>Which limit a spend breaks (with top-ups applied), as words, or null.</summary>
    internal static (string Period, string Reason)? Exceeded(double dayUsd, long dayTokens, double monthUsd, long monthTokens,
        double? dailyUsd, double? monthlyUsd, long? dailyTokens, long? monthlyTokens, double topupUsd, long topupTokens)
    {
        if (monthlyUsd is { } mu && monthUsd >= mu + topupUsd) return ("month", $"monthly spend ${monthUsd:0.00} reached the ${mu + topupUsd:0.00} limit");
        if (monthlyTokens is { } mt && monthTokens >= mt + topupTokens) return ("month", $"monthly tokens {monthTokens:N0} reached the {mt + topupTokens:N0} limit");
        if (dailyUsd is { } du && dayUsd >= du + topupUsd) return ("day", $"daily spend ${dayUsd:0.00} reached the ${du + topupUsd:0.00} limit");
        if (dailyTokens is { } dt && dayTokens >= dt + topupTokens) return ("day", $"daily tokens {dayTokens:N0} reached the {dt + topupTokens:N0} limit");
        return null;
    }

    /// <summary>Highest share of any limit used (0-1+), for the soft alert.</summary>
    internal static double Burn(double dayUsd, long dayTokens, double monthUsd, long monthTokens,
        double? dailyUsd, double? monthlyUsd, long? dailyTokens, long? monthlyTokens, double topupUsd, long topupTokens)
    {
        static double R(double spent, double? limit, double extra) => limit is { } l && l + extra > 0 ? spent / (l + extra) : 0;
        return new[]
        {
            R(dayUsd, dailyUsd, topupUsd), R(monthUsd, monthlyUsd, topupUsd),
            R(dayTokens, dailyTokens, topupTokens), R(monthTokens, monthlyTokens, topupTokens),
        }.Max();
    }

    /// <summary>
    /// Re-checks an agent against its budget: soft alert once per period, hard cap (release claims, notice, audit, alert),
    /// and clears a block an admin change or new spend picture has lifted. Returns the position.
    /// </summary>
    /// <remarks>
    /// Evaluate, block and clear run in one transaction under a per-principal advisory lock, so concurrent evaluations
    /// (metering on parallel calls, a report, the sweep, an admin change) queue and each sees the last one's result: they
    /// can't flip block and clear against each other. The #general notice and approver alert go out once per period
    /// (<c>notified_at</c>), however often a block is cleared and re-applied in it; every block and clear is audited.
    /// </remarks>
    /// <param name="adminChange">An admin raised, removed or topped up the budget: clear any block first (then re-check).</param>
    public async Task<BudgetPosition?> EvaluateAsync(Guid principalId, CancellationToken ct = default, string? adminChange = null)
    {
        Limits? limits;
        double dayUsd = 0, monthUsd = 0;
        long dayTokens = 0, monthTokens = 0;
        (string Period, string Reason)? exceeded = null;
        var burn = 0d;
        var cleared = false;
        var newlyBlocked = false;
        var notify = false;
        var softAlert = false;
        var released = 0;
        await using (var conn = await db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            await using (var lk = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('budget:' || @p::text))", conn, tx).With("p", principalId))
                await lk.ExecuteNonQueryAsync(ct);
            limits = await LimitsAsync(conn, tx, principalId, ct);
            if (adminChange is not null || limits is null)
                cleared = await ClearBlocksAsync(conn, tx, principalId, adminChange ?? "no budget", ct);
            if (limits is not null)
            {
                (dayUsd, dayTokens, monthUsd, monthTokens) = await SpendAsync(conn, tx, principalId, ct);
                exceeded = Exceeded(dayUsd, dayTokens, monthUsd, monthTokens, limits.DailyUsd, limits.MonthlyUsd, limits.DailyTokens, limits.MonthlyTokens, limits.TopupUsd, limits.TopupTokens);
                burn = Burn(dayUsd, dayTokens, monthUsd, monthTokens, limits.DailyUsd, limits.MonthlyUsd, limits.DailyTokens, limits.MonthlyTokens, limits.TopupUsd, limits.TopupTokens);
                if (exceeded is { } x)
                {
                    (newlyBlocked, notify) = await BlockAsync(conn, tx, principalId, x.Period, x.Reason, ct);
                    if (newlyBlocked)
                        await using (var rel = new NpgsqlCommand("""
                            update messages set claim_state = 'open', claimed_by = null, claim_expires_at = null
                            where claimed_by = @p and claim_state = 'claimed'
                            """, conn, tx).With("p", principalId))
                            released = await rel.ExecuteNonQueryAsync(ct);
                }
                else
                {
                    cleared |= await ClearBlocksAsync(conn, tx, principalId, "spend is within budget", ct);
                    if (burn * 100 >= limits.SoftPct)
                        await using (var soft = new NpgsqlCommand("""
                            insert into agent_budget_state as s (principal_id, period, period_start, soft_alerted_at)
                            values (@p, 'month', date_trunc('month', now() at time zone 'utc')::date, now())
                            on conflict (principal_id, period, period_start) do update set soft_alerted_at = now() where s.soft_alerted_at is null
                            returning 1
                            """, conn, tx).With("p", principalId))
                            softAlert = await soft.ExecuteScalarAsync(ct) is not null;
                }
            }
            await tx.CommitAsync(ct);
        }

        // Side effects after commit, decided under the lock, so each happens once.
        if (cleared || newlyBlocked || softAlert)
        {
            var handle = await HandleAsync(principalId, ct);
            var sys = await system.GetAsync(ct);
            if (cleared && !newlyBlocked) await audit.WriteAsync(sys.Id, "agent.budget_cleared", handle, new { why = adminChange ?? "spend is within budget" }, ct);
            if (newlyBlocked && exceeded is { } x)
            {
                await audit.WriteAsync(sys.Id, "agent.budget_exceeded", handle,
                    new { period = x.Period, reason = x.Reason, spend = new { day_usd = dayUsd, month_usd = monthUsd, day_tokens = dayTokens, month_tokens = monthTokens }, released_claims = released, notified = notify }, ct);
                if (notify)
                {
                    await board.PostAsync(sys, new PostInput("general",
                        $"@{handle} is **over budget** ({x.Reason}). The board refuses its MCP and REST calls until the {(x.Period == "day" ? "next UTC day" : "next UTC month")} or an admin raises its budget or grants a top-up on Agents.{(released > 0 ? $" Released {released} claim(s) it held." : "")}",
                        "status", Json.Element(new { state = "agent_budget_exceeded", handle, period = x.Period })), system: true, ct);
                    await AlertAsync("agent.budget_exceeded", $"@{handle} is over budget", handle, x.Reason, ct);
                }
            }
            if (softAlert && limits is not null)
            {
                var pct = (int)Math.Floor(burn * 100);
                await audit.WriteAsync(sys.Id, "agent.budget_soft_alert", handle, new { used_pct = pct, soft_pct = limits.SoftPct }, ct);
                await board.PostAsync(sys, new PostInput("general",
                    $"@{handle} has used {pct}% of a budget limit (alert at {limits.SoftPct}%). An admin can review it on Agents.",
                    "status", Json.Element(new { state = "agent_budget_soft_alert", handle, used_pct = pct })), system: true, ct);
                await AlertAsync("agent.budget_soft_alert", $"@{handle} at {pct}% of budget", handle, $"alert threshold {limits.SoftPct}%", ct);
            }
        }
        return limits is null ? null : new BudgetPosition(Math.Round(dayUsd, 4), dayTokens, Math.Round(monthUsd, 4), monthTokens,
            limits.DailyUsd, limits.MonthlyUsd, limits.DailyTokens, limits.MonthlyTokens, limits.SoftPct, exceeded is not null);
    }

    private const string PeriodStart = "case when @per = 'day' then (now() at time zone 'utc')::date else date_trunc('month', now() at time zone 'utc')::date end";

    /// <summary>Blocks for the period. Newly: it wasn't blocked a moment ago. Notify: nobody was told yet this period.</summary>
    private static async Task<(bool Newly, bool Notify)> BlockAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Guid principalId, string period, string reason, CancellationToken ct)
    {
        await using (var cmd = new NpgsqlCommand($"""
            insert into agent_budget_state as s (principal_id, period, period_start, exceeded_at, detail)
            values (@p, @per, {PeriodStart}, now(), jsonb_build_object('reason', @r::text))
            on conflict (principal_id, period, period_start) do update
              set exceeded_at = now(), cleared_at = null, detail = jsonb_build_object('reason', @r::text)
              where s.exceeded_at is null or s.cleared_at is not null
            returning 1
            """, conn, tx).With("p", principalId).With("per", period).With("r", reason))
            if (await cmd.ExecuteScalarAsync(ct) is null) return (false, false);
        await using var mark = new NpgsqlCommand($"""
            update agent_budget_state set notified_at = now()
            where principal_id = @p and period = @per and period_start = {PeriodStart} and notified_at is null returning 1
            """, conn, tx).With("p", principalId).With("per", period);
        return (true, await mark.ExecuteScalarAsync(ct) is not null);
    }

    private static async Task<bool> ClearBlocksAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Guid principalId, string why, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            update agent_budget_state set cleared_at = now(), detail = coalesce(detail, '{}') || jsonb_build_object('cleared', @w::text)
            where principal_id = @p and exceeded_at is not null and cleared_at is null
            """, conn, tx).With("p", principalId).With("w", why);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    private async Task AlertAsync(string evt, string headline, string handle, string detail, CancellationToken ct)
    {
        if (notifier is null) return;
        try { await notifier.AlertApproversAsync(evt, headline, handle, detail, "/agents", ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "agent alert {Event} failed", evt); }
    }

    private async Task<string> HandleAsync(Guid principalId, CancellationToken ct)
    {
        await using var cmd = db.Command("select handle from principals where id = @p").With("p", principalId);
        return await cmd.ExecuteScalarAsync(ct) as string ?? principalId.ToString();
    }

    // ── admin (people with Board.Admin only; REST, never MCP) ─────────────────────────────────────

    private static void RequireHumanAdmin(Principal me)
    {
        me.Require(Roles.Admin);
        if (!me.IsHuman) throw BoardException.Forbidden("only people can change agent budgets");
    }

    private async Task<Guid> AgentIdAsync(string handle, CancellationToken ct)
    {
        await using var cmd = db.Command("select id, kind from principals where handle = @h").With("h", handle.TrimStart('@'));
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) throw BoardException.NotFound("principal");
        if (r.GetString(1) != "agent") throw new BoardException("budgets apply to agents only");
        return r.GetGuid(0);
    }

    public async Task<AgentBudgetRow> SetBudgetAsync(Principal me, string handle, BudgetInput b, CancellationToken ct = default)
    {
        RequireHumanAdmin(me);
        if (b.Reason.Trim() is not { Length: >= 5 and <= 500 } reason) throw new BoardException("reason must be 5–500 characters");
        var id = await AgentIdAsync(handle, ct);
        await using (var cmd = db.Command("""
            insert into agent_budgets (principal_id, daily_usd, monthly_usd, daily_tokens, monthly_tokens, soft_pct, note, updated_by, updated_at)
            values (@p, @du, @mu, @dt, @mt, @soft, @note, @by, now())
            on conflict (principal_id) do update set daily_usd = excluded.daily_usd, monthly_usd = excluded.monthly_usd,
              daily_tokens = excluded.daily_tokens, monthly_tokens = excluded.monthly_tokens, soft_pct = excluded.soft_pct,
              note = excluded.note, updated_by = excluded.updated_by, updated_at = now()
            """).With("p", id).With("du", b.DailyUsd is { } du ? (decimal)du : null).With("mu", b.MonthlyUsd is { } mu ? (decimal)mu : null)
                .With("dt", b.DailyTokens).With("mt", b.MonthlyTokens).With("soft", b.SoftPct).With("note", reason).With("by", me.Id))
            await cmd.ExecuteNonQueryAsync(ct);
        await audit.WriteAsync(me.Id, "agent.budget_set", handle, new { b.DailyUsd, b.MonthlyUsd, b.DailyTokens, b.MonthlyTokens, b.SoftPct, reason }, ct);
        // A raised budget lifts the block now; a lowered one may block now (one locked step).
        await EvaluateAsync(id, ct, $"budget changed by @{me.Handle}");
        return (await ListAsync(me, ct)).First(x => x.PrincipalId == id);
    }

    public async Task<AgentBudgetRow> RemoveBudgetAsync(Principal me, string handle, string? reasonIn, CancellationToken ct = default)
    {
        RequireHumanAdmin(me);
        if (reasonIn?.Trim() is not { Length: >= 5 and <= 500 } reason) throw new BoardException("reason must be 5–500 characters");
        var id = await AgentIdAsync(handle, ct);
        await using (var cmd = db.Command("delete from agent_budgets where principal_id = @p").With("p", id))
            await cmd.ExecuteNonQueryAsync(ct);
        await audit.WriteAsync(me.Id, "agent.budget_removed", handle, new { reason }, ct);
        await EvaluateAsync(id, ct, $"budget removed by @{me.Handle}");
        return (await ListAsync(me, ct)).First(x => x.PrincipalId == id);
    }

    public async Task<AgentBudgetRow> TopUpAsync(Principal me, string handle, TopupInput t, CancellationToken ct = default)
    {
        RequireHumanAdmin(me);
        if (t.Reason.Trim() is not { Length: >= 5 and <= 500 } reason) throw new BoardException("reason must be 5–500 characters");
        if (t.Usd <= 0 && t.Tokens <= 0) throw new BoardException("top up some USD or tokens");
        var id = await AgentIdAsync(handle, ct);
        await using (var exists = db.Command("select 1 from agent_budgets where principal_id = @p").With("p", id))
            if (await exists.ExecuteScalarAsync(ct) is null) throw new BoardException("set a budget before granting a top-up");
        await using (var cmd = db.Command("""
            insert into agent_budget_topups (principal_id, usd, tokens, expires_at, reason, granted_by)
            values (@p, @u, @t, now() + make_interval(hours => @h), @r, @by)
            """).With("p", id).With("u", (decimal)t.Usd).With("t", t.Tokens).With("h", t.Hours).With("r", reason).With("by", me.Id))
            await cmd.ExecuteNonQueryAsync(ct);
        await audit.WriteAsync(me.Id, "agent.budget_topup", handle, new { t.Usd, t.Tokens, t.Hours, reason }, ct);
        await EvaluateAsync(id, ct, $"top-up by @{me.Handle}");
        return (await ListAsync(me, ct)).First(x => x.PrincipalId == id);
    }

    /// <summary>Every agent with its budget (if any), spend and reporting health. Board.Admin.</summary>
    public async Task<IReadOnlyList<AgentBudgetRow>> ListAsync(Principal me, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        await using var cmd = db.Command("""
            with b as (select (now() at time zone 'utc')::date as d0, date_trunc('month', now() at time zone 'utc')::date as m0)
            select p.id, p.handle, p.display_name, p.enabled,
                   g.daily_usd, g.monthly_usd, g.daily_tokens, g.monthly_tokens, coalesce(g.soft_pct, 80), g.note, ub.handle, g.updated_at,
                   coalesce((select sum(cost_usd) from agent_usage u where u.principal_id = p.id and u.created_at >= b.d0::timestamp at time zone 'utc'), 0)
                     + coalesce((select sum(cost_usd) from agent_metered_daily m where m.principal_id = p.id and m.day = b.d0), 0),
                   coalesce((select sum(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens) from agent_usage u where u.principal_id = p.id and u.created_at >= b.d0::timestamp at time zone 'utc'), 0),
                   coalesce((select sum(cost_usd) from agent_usage u where u.principal_id = p.id and u.created_at >= b.m0::timestamp at time zone 'utc'), 0)
                     + coalesce((select sum(cost_usd) from agent_metered_daily m where m.principal_id = p.id and m.day >= b.m0), 0),
                   coalesce((select sum(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens) from agent_usage u where u.principal_id = p.id and u.created_at >= b.m0::timestamp at time zone 'utc'), 0),
                   coalesce((select sum(usd) from agent_budget_topups t where t.principal_id = p.id and t.expires_at > now()), 0),
                   coalesce((select sum(tokens) from agent_budget_topups t where t.principal_id = p.id and t.expires_at > now()), 0),
                   (select s.detail->>'reason' from agent_budget_state s where s.principal_id = p.id and s.exceeded_at is not null and s.cleared_at is null
                      and ((s.period = 'day' and s.period_start = b.d0) or (s.period = 'month' and s.period_start = b.m0)) limit 1),
                   (select max(created_at) from agent_usage u where u.principal_id = p.id),
                   coalesce((select sum(calls) from agent_metered_daily m where m.principal_id = p.id and m.day > b.d0 - 7
                             and not exists (select 1 from agent_usage u where u.principal_id = p.id and u.created_at > now() - interval '7 days')), 0)
            from principals p cross join b
            left join agent_budgets g on g.principal_id = p.id
            left join principals ub on ub.id = g.updated_by
            where p.kind = 'agent'
            order by p.enabled desc, p.handle
            limit 500
            """);
        var list = new List<AgentBudgetRow>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            var blockedReason = r.IsDBNull(18) ? null : r.GetString(18);
            list.Add(new AgentBudgetRow(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetBoolean(3),
                r.IsDBNull(4) ? null : (double)r.GetDecimal(4), r.IsDBNull(5) ? null : (double)r.GetDecimal(5),
                r.IsDBNull(6) ? null : r.GetInt64(6), r.IsDBNull(7) ? null : r.GetInt64(7), r.GetInt32(8),
                r.IsDBNull(9) ? null : r.GetString(9), r.IsDBNull(10) ? null : r.GetString(10), r.IsDBNull(11) ? null : r.GetFieldValue<DateTimeOffset>(11),
                Math.Round((double)r.GetDecimal(12), 4), (long)r.GetDecimal(13), Math.Round((double)r.GetDecimal(14), 4), (long)r.GetDecimal(15),
                (double)r.GetDecimal(16), (long)r.GetDecimal(17), blockedReason is not null, blockedReason,
                r.IsDBNull(19) ? null : r.GetFieldValue<DateTimeOffset>(19), (int)r.GetDecimal(20)));
        }
        return list;
    }

    /// <summary>Re-evaluates every agent with a budget (timer): top-ups expiring, a new period starting.</summary>
    public async Task<int> SweepAsync(CancellationToken ct = default)
    {
        var ids = new List<Guid>();
        await using (var cmd = db.Command("select principal_id from agent_budgets"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) ids.Add(r.GetGuid(0));
        var blocked = 0;
        foreach (var id in ids)
            if ((await EvaluateAsync(id, ct))?.Blocked == true) blocked++;
        return blocked;
    }
}
