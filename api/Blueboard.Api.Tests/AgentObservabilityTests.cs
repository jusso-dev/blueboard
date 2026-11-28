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
        Assert.Equal(PriceTable.DefaultToolPriceUsd, p.ToolPrice("read_feed"));
        Assert.Equal(0, p.ToolPrice("whoami"));
        Assert.Equal(0, p.ToolPrice("report_usage"));
        var free = new PriceTable("""{"default_tool":0,"tools":{"report_usage":5}}""");
        Assert.Equal(0, free.ToolPrice("read_feed"));
        Assert.Equal(0, free.ToolPrice("report_usage"));
        Assert.Throws<InvalidOperationException>(() => new PriceTable("""{"default_tool":-1}"""));
        Assert.Throws<InvalidOperationException>(() => new PriceTable("""{"default_tool":"x"}"""));
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
    [Fact]
    public void Release_exemption_reads_the_outcome_exactly_as_complete_claim_does()
    {
        JsonElement J(string s) => JsonDocument.Parse(s).RootElement;
        var id = Guid.NewGuid();
        Assert.Equal("release", McpObserver.ClaimOutcome(J($$"""{"message_id":"{{id}}","outcome":"release"}""")));
        // Mixed case is not a valid outcome for the tool, so it is no exemption either.
        Assert.Null(McpObserver.ClaimOutcome(J($$"""{"message_id":"{{id}}","outcome":"Release"}""")));
        // Duplicate keys: the contract (case-insensitive, last wins) reads "done", so the exemption does too.
        Assert.Equal("done", McpObserver.ClaimOutcome(J($$"""{"message_id":"{{id}}","outcome":"release","OUTCOME":"done"}""")));
        Assert.Equal("done", McpObserver.ClaimOp(J("""{"op":"release","OP":"done"}""")));
        Assert.Equal("release", McpObserver.ClaimOp(J("""{"op":"release"}""")));
    }

    [Fact]
    public void Rest_route_labels_name_the_route_not_the_record()
    {
        Assert.Equal("rest:POST /api/actions", Http.Endpoint.RouteLabel("post", "/api/actions"));
        Assert.Equal("rest:POST /api/claims/{id}", Http.Endpoint.RouteLabel("POST", $"/api/claims/{Guid.NewGuid()}"));
        Assert.Equal("rest:GET /api/incidents/{id}/timeline", Http.Endpoint.RouteLabel("GET", "/api/incidents/90210/timeline"));
        Assert.Equal(McpObserver.RestWhoAmI, Http.Endpoint.RouteLabel("GET", "/api/me"));
        Assert.Equal(0, new PriceTable().ToolPrice(McpObserver.RestWhoAmI));
        Assert.Equal(PriceTable.DefaultToolPriceUsd, new PriceTable().ToolPrice("rest:POST /api/actions"));
    }
    private const string BareJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiYXBpOi8veCJ9.c2lnbmF0dXJlLXZhbHVlLWhlcmU";

    [Theory]
    [InlineData("token: " + BareJwt)]
    [InlineData("https://acct.blob.core.windows.net/c/f?sv=2022-11-02&ss=b&srt=o&sp=r&se=2026-12-01T00:00:00Z&sig=abcdEFGHijklMNOPqrstUVWXyz0123456789%2BABCDE%3D")]
    [InlineData("Server=tcp:db.contoso.com,1433;Initial Catalog=prod;User ID=svc;Password=Hunter2!Secret;")]
    [InlineData("Data Source=sql01;Database=hr;uid=sa;pwd=S3cretPass")]
    [InlineData("Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=")]
    [InlineData("DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==")]
    public void Secret_leak_detector_catches_bare_jwts_sas_and_connection_string_secrets(string text) =>
        Assert.NotNull(Board.BoardService.DetectSecretLeak(text));

    [Theory]
    // Ordinary SOC text must still post.
    [InlineData("User reset their password=yes per helpdesk ticket; no further action.")]
    [InlineData("Process ran: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]
    [InlineData("sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 seen on ws-042")]
    [InlineData("Phishing URL https://evil.example/login?sig=abc&id=42 blocked")]
    [InlineData("Header eyJ is base64 for a JSON brace; not a token.")]
    [InlineData("eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl has no alg, so it is not a JWT")]
    [InlineData("Device 4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d, incident 90210, user ana@contoso.com")]
    public void Secret_leak_detector_lets_ordinary_soc_text_through(string text) =>
        Assert.Null(Board.BoardService.DetectSecretLeak(text));

    [Fact]
    public void Bare_jwt_needs_three_segments_and_an_alg_header()
    {
        Assert.True(Board.BoardService.IsJwt(BareJwt));
        Assert.False(Board.BoardService.IsJwt("eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl"));
        Assert.False(Board.BoardService.IsJwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"));
        Assert.False(Board.BoardService.IsJwt("eyJ!!!.eyJ.x"));
    }

    [Theory]
    [InlineData("x-api-key")] [InlineData("X-Api-Key")] [InlineData("api_key")] [InlineData("access_key")] [InlineData("AccessKey")]
    [InlineData("auth")] [InlineData("Authorization")] [InlineData("client_secret")] [InlineData("private_key")] [InlineData("Cookie")]
    [InlineData("set-cookie")] [InlineData("sig")] [InlineData("connection_string")] [InlineData("pwd")]
    public void Sensitive_key_names_are_redacted_case_insensitively(string key)
    {
        Assert.True(TraceRedactor.IsSensitiveKey(key));
        var s = TraceRedactor.Summarise(JsonSerializer.SerializeToElement(new Dictionary<string, object> { [key] = "value-123" }))!;
        Assert.Equal("[redacted]", s[key]!.GetValue<string>());
    }

    [Theory]
    [InlineData("author")] [InlineData("oauth_app")] [InlineData("message_id")] [InlineData("query")] [InlineData("signal")] [InlineData("path")]
    public void Ordinary_argument_names_are_kept(string key) => Assert.False(TraceRedactor.IsSensitiveKey(key));
}
