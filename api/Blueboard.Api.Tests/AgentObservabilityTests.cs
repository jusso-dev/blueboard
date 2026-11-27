using System.Text.Json;
using Blueboard.Api.Agents;
using Blueboard.Api.Core;
using Blueboard.Api.Mcp;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>WS3 pure logic: price table, trace redaction, budget arithmetic, the risk model, and the MCP surface.</summary>
public class AgentObservabilityTests
{
    [Fact]
    public void Price_table_prices_known_models_and_their_suffixed_ids()
    {
        var p = new PriceTable();
        Assert.Equal(4.0, p.For("claude-opus-5-5")!.Cost(1_000_000, 0, 0, 0), 6);
        Assert.Equal(20.0, p.For("claude-opus-5-5")!.Cost(0, 1_000_000, 0, 0), 6);
        Assert.Equal(0.2, p.For("claude-opus-5-5")!.Cost(0, 0, 1_000_000, 0), 6);
        Assert.Same(p.For("claude-opus-5-5"), p.For("claude-opus-5-5[1m]"));
        Assert.Same(p.For("claude-haiku-4-5"), p.For("claude-haiku-4-5-20251001"));
        Assert.Same(p.For("claude-opus-5-5"), p.For("anthropic.claude-opus-5-5"));
        // claude-opus-5 must not swallow claude-opus-5-5, nor claude-opus-5-9 (unknown) be priced as Opus 5.
        Assert.NotSame(p.For("claude-opus-5"), p.For("claude-opus-5-5"));
        Assert.Null(p.For("claude-opus-5-9"));
        Assert.Null(p.For("gpt-something"));
    }

    [Fact]
    public void Price_table_overrides_are_strict()
    {
        var p = new PriceTable("""{"models":{"my-model":{"input":1,"output":2}},"tools":{"run_hunting_query":0.01}}""");
        Assert.Equal(3.0, p.For("my-model")!.Cost(1_000_000, 1_000_000, 0, 0), 6);
        Assert.Equal(0.01, p.ToolPrice("run_hunting_query"));
        Assert.Equal(0, p.ToolPrice("read_feed"));
        Assert.Throws<InvalidOperationException>(() => new PriceTable("""{"models":{"x":{"input":-1,"output":2}}}"""));
        Assert.Throws<InvalidOperationException>(() => new PriceTable("""{"other":{}}"""));
        Assert.Throws<InvalidOperationException>(() => new PriceTable("not json"));
    }

    [Fact]
    public void Trace_summary_drops_secrets_sensitive_keys_and_caps_size()
    {
        var secret = "sk-ant-api03-" + new string('x', 40);
        var args = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
        {
            ["channel"] = "triage",
            ["body"] = $"here is the key {secret}",
            ["webhook_secret"] = "plain-looking-value",
            ["access_token"] = "abc",
            ["long"] = new string('a', 5000),
            ["list"] = Enumerable.Range(0, 30).ToArray(),
            ["payload"] = new { a = new { b = new { c = new { d = 1 } } } },
        });
        var s = TraceRedactor.Summarise(args)!;
        var json = s.ToJsonString();
        Assert.DoesNotContain("sk-ant-api03", json);
        Assert.DoesNotContain("plain-looking-value", json);
        Assert.Equal(TraceRedactor.Redacted, s["body"]!.GetValue<string>());
        Assert.Equal("[redacted]", s["access_token"]!.GetValue<string>());
        Assert.True(s["long"]!.GetValue<string>().Length < 220);
        Assert.Equal(TraceRedactor.MaxItems + 1, s["list"]!.AsArray().Count);
        Assert.True(json.Length <= TraceRedactor.MaxBytes);
    }

    [Fact]
    public void Trace_keeps_kql_only_for_hunting_tools_and_never_with_a_secret()
    {
        var q = JsonSerializer.SerializeToElement(new { query = "DeviceEvents | take 5" });
        Assert.Equal("DeviceEvents | take 5", TraceRedactor.Kql("run_hunting_query", q));
        Assert.Null(TraceRedactor.Kql("post_message", q));
        var leak = JsonSerializer.SerializeToElement(new { query = "DeviceEvents | where x == '" + "AKIA" + "ABCDEFGHIJKLMNOP'" });
        Assert.Null(TraceRedactor.Kql("run_sentinel_query", leak));
    }

    [Fact]
    public void Trace_links_the_message_an_argument_names()
    {
        var id = Guid.NewGuid();
        Assert.Equal(id, AgentTrace.NamedMessage(JsonSerializer.SerializeToElement(new { message_id = id })));
        Assert.Equal(id, AgentTrace.NamedMessage(JsonSerializer.SerializeToElement(new { parent_id = id.ToString(), channel = "x" })));
        Assert.Null(AgentTrace.NamedMessage(JsonSerializer.SerializeToElement(new { message_id = "nope" })));
    }

    [Fact]
    public void Budget_limits_include_top_ups_and_name_the_period()
    {
        Assert.Null(AgentBudgets.Exceeded(0.99, 0, 5, 0, 1, 100, null, null, 0, 0));
        Assert.Equal("day", AgentBudgets.Exceeded(1.0, 0, 5, 0, 1, 100, null, null, 0, 0)!.Value.Period);
        Assert.Null(AgentBudgets.Exceeded(1.5, 0, 5, 0, 1, 100, null, null, 1, 0)); // a $1 top-up covers it
        Assert.Equal("month", AgentBudgets.Exceeded(0, 0, 0, 2_000_000, null, null, null, 1_000_000, 0, 0)!.Value.Period);
        Assert.Equal(0.8, AgentBudgets.Burn(0.8, 0, 0, 0, 1, null, null, null, 0, 0), 6);
        Assert.Equal(0, AgentBudgets.Burn(5, 5, 5, 5, null, null, null, null, 0, 0));
    }

    [Fact]
    public void Forecast_is_a_straight_line_to_month_end() =>
        Assert.Equal(300, AgentReports.Forecast(100, 10, 30), 6);

    private static RiskInputs Quiet() => new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    [Fact]
    public void Risk_is_zero_for_a_quiet_agent_and_capped_at_100()
    {
        Assert.Equal(0, RiskModel.Score(Quiet()).Score);
        var bad = new RiskInputs(50, 50, 50, 50, 50, 10, 10, 10, 10, 10_000, 10, 10, 50);
        Assert.Equal(100, RiskModel.Score(bad).Score);
    }

    [Fact]
    public void Risk_factors_respect_their_caps_and_minimum_samples()
    {
        var (_, f) = RiskModel.Score(Quiet() with { ProtectedTargetAttempts = 10 });
        Assert.Equal(30, f.Single(x => x.Key == "protected_target_attempts").Points);
        // Two judged verdicts, both wrong: below the minimum sample, so no overturn points yet.
        Assert.Equal(0, RiskModel.Score(Quiet() with { ResolvedVerdicts = 2, Overturns = 2 }).Factors.Single(x => x.Key == "overturn_rate").Points);
        Assert.Equal(25, RiskModel.Score(Quiet() with { ResolvedVerdicts = 4, Overturns = 4 }).Factors.Single(x => x.Key == "overturn_rate").Points);
    }

    [Fact]
    public void Unusual_volume_needs_a_baseline_and_a_real_spike()
    {
        int Vol(RiskInputs x) => RiskModel.Score(x).Factors.Single(f => f.Key == "unusual_volume").Points;
        Assert.Equal(0, Vol(Quiet() with { CallsLast24h = 1000, BaselineDailyCalls = 100, BaselineDays = 2 })); // too little history
        Assert.Equal(0, Vol(Quiet() with { CallsLast24h = 250, BaselineDailyCalls = 100, BaselineDays = 10 })); // 2.5x: normal
        Assert.Equal(15, Vol(Quiet() with { CallsLast24h = 1000, BaselineDailyCalls = 100, BaselineDays = 10 }));
        Assert.Equal(0, Vol(Quiet() with { CallsLast24h = 30, BaselineDailyCalls = 1, BaselineDays = 10 })); // tiny absolute volume
    }

    [Fact]
    public void Mcp_exposes_usage_and_feedback_but_no_budget_or_threshold_control()
    {
        Assert.Contains(Tools.All, x => x.Name == "report_usage" && x.Role is null);
        Assert.Contains(Tools.All, x => x.Name == "get_agent_feedback");
        foreach (var t in Tools.All)
            Assert.DoesNotMatch("budget|topup|top_up|threshold|quarantine|risk|price|feedback_set|give_feedback", t.Name);
        Assert.Equal(["complete_claim", "report_usage", "whoami"], AgentBudgets.AllowedWhenBlocked.Order());
    }

    [Fact]
    public void Usage_report_contract_bounds_token_counts()
    {
        Assert.Throws<ContractException>(() => Contract.Read<UsageReportInput>(JsonSerializer.SerializeToElement(new { model = "claude-opus-5-5", input_tokens = -1 })));
        Assert.Throws<ContractException>(() => Contract.Read<UsageReportInput>(JsonSerializer.SerializeToElement(new { model = "claude-opus-5-5", output_tokens = 60_000_000 })));
        Assert.Throws<ContractException>(() => Contract.Read<UsageReportInput>(JsonSerializer.SerializeToElement(new { model = "bad model with spaces" })));
        var ok = Contract.Read<UsageReportInput>(JsonSerializer.SerializeToElement(new { model = "claude-opus-5-5[1m]", input_tokens = 10, cache_read_tokens = 5 }));
        Assert.Equal(5, ok.CacheReadTokens);
    }

    [Fact]
    public void Trace_status_classifies_board_errors()
    {
        Assert.Equal("budget_blocked", McpObserver.StatusOf(new BoardException("x", 402) { Bucket = "budget" }));
        Assert.Equal("secret_blocked", McpObserver.StatusOf(new BoardException("x") { Bucket = McpObserver.SecretLeakBucket }));
        Assert.Equal("rate_limited", McpObserver.StatusOf(BoardException.RateLimited("post", 3)));
        Assert.Equal("forbidden", McpObserver.StatusOf(BoardException.Forbidden("no")));
        Assert.Equal("error", McpObserver.StatusOf(BoardException.NotFound("x")));
    }
}
