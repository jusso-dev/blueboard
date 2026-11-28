using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Agents;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>WS3: hard budget cap over MCP, usage validation, overturn detection, feedback, tool-call traces and risk.</summary>
public sealed class AgentObservabilityTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A fresh agent per test so budgets, usage and traces never carry over.</summary>
    private async Task<Principal> NewAgent()
    {
        var handle = $"obs-{Guid.NewGuid():N}"[..20];
        await using (var c = t.Db.Command("insert into principals (handle, display_name, kind, roles) values (@h, @h, 'agent', @r)")
                         .With("h", handle).With("r", new[] { "poster", "hunter", "requester" }))
            await c.ExecuteNonQueryAsync(Ct);
        return await t.As(handle);
    }

    private static Dictionary<string, object> Usage(long input, long output, string model = "claude-opus-5-5", string? requestId = null)
    {
        var d = new Dictionary<string, object> { ["model"] = model, ["input_tokens"] = input, ["output_tokens"] = output };
        if (requestId is not null) d["request_id"] = requestId;
        return d;
    }

    [DbFact]
    public async Task Over_budget_agent_is_refused_except_whoami_report_and_release_and_claims_are_released()
    {
        var app = A1.Build(t, new Policy());
        var tools = A1.Tools(app);
        var agent = await NewAgent();
        var admin = await t.As("analyst");
        await app.Budgets.SetBudgetAsync(admin, agent.Handle, new BudgetInput(DailyUsd: 1, Reason: "integration test budget"), Ct);

        // The agent claims a question, then reports usage that pushes it over $1 (200k output tokens on Opus 5.5 = $4).
        var q = await t.Board.PostAsync(admin, new PostInput("triage", "Is 203.0.113.50 known?", "question"), ct: Ct);
        Assert.DoesNotContain("error", await tools.ClaimMessage(A1.Mcp("claim_message", agent.Handle, new() { ["message_id"] = q.Id.ToString() })));
        var receipt = await tools.ReportUsage(A1.Mcp("report_usage", agent.Handle, Usage(1000, 200_000, requestId: "req-1")));
        Assert.DoesNotContain("error", receipt);
        Assert.Contains("\"blocked\":true", receipt);

        // Refused with a clear error; whoami and report_usage still work.
        var refused = await tools.ReadFeed(A1.Mcp("read_feed", agent.Handle));
        Assert.StartsWith("error: budget exceeded", refused);
        Assert.Contains("(status 402)", refused);
        Assert.DoesNotContain("error", await tools.WhoAmI(A1.Mcp("whoami", agent.Handle)));
        Assert.DoesNotContain("error", await tools.ReportUsage(A1.Mcp("report_usage", agent.Handle, Usage(10, 10, requestId: "req-2"))));

        // Its claim was released when it went over; release is allowed, done is not.
        Assert.Equal("open", (await t.Board.GetAsync(q.Id, Ct))!.ClaimState);
        Assert.StartsWith("error: budget exceeded", await tools.CompleteClaim(A1.Mcp("complete_claim", agent.Handle, new() { ["message_id"] = q.Id.ToString(), ["outcome"] = "done" })));

        // One notice in #general and one audit row, however many reports follow.
        await tools.ReportUsage(A1.Mcp("report_usage", agent.Handle, Usage(10, 10, requestId: "req-3")));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'agent.budget_exceeded' and subject = @h", ("h", agent.Handle)));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from messages where payload->>'state' = 'agent_budget_exceeded' and payload->>'handle' = @h", ("h", agent.Handle)));

        // The refused call is in the trace as budget_blocked.
        Assert.True(await t.ScalarAsync("select count(*) from agent_tool_calls where principal_id = @p and tool = 'read_feed' and status = 'budget_blocked'", ("p", agent.Id)) >= 1);

        // A top-up lifts the block at once.
        await app.Budgets.TopUpAsync(admin, agent.Handle, new TopupInput(Usd: 10, Hours: 1, Reason: "integration test top-up"), Ct);
        Assert.DoesNotContain("error", await tools.ReadFeed(A1.Mcp("read_feed", agent.Handle)));
    }

    [DbFact]
    public async Task Over_budget_agent_is_refused_on_rest_too_and_rest_calls_are_metered_and_traced()
    {
        var app = A1.Build(t, new Policy());
        var agent = await NewAgent();
        var admin = await t.As("analyst");
        await app.Budgets.SetBudgetAsync(admin, agent.Handle, new BudgetInput(DailyUsd: 0.025, Reason: "integration test budget"), Ct);
        var q = await t.Board.PostAsync(admin, new PostInput("triage", "Is 198.51.100.7 known?", "question"), ct: Ct);

        // Under budget: REST works, and every call is metered ($0.01 default) and traced under a route label.
        var (claimed, _) = A1.Read(await app.Api.Claim(A1.Request(agent.Handle, "POST", new { op = "claim" }, path: $"/api/claims/{q.Id}"), q.Id.ToString()));
        Assert.Equal(200, claimed);
        Assert.Equal(200, A1.Read(await app.Api.Messages(A1.Request(agent.Handle, path: "/api/messages", query: "?channel=triage"))).Status);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from agent_tool_calls where principal_id = @p and tool = 'rest:POST /api/claims/{id}' and status = 'ok'", ("p", agent.Id)));
        Assert.Equal(1, await t.ScalarAsync("select calls from agent_metered_daily where principal_id = @p and tool = 'rest:GET /api/messages'", ("p", agent.Id)));

        // A third priced call ($0.03) takes it over $0.025: REST is now refused with 402, like MCP.
        A1.Read(await app.Api.Messages(A1.Request(agent.Handle, path: "/api/messages", query: "?channel=triage")));
        var (refused, body) = A1.Read(await app.Api.Messages(A1.Request(agent.Handle, path: "/api/messages", query: "?channel=triage")));
        Assert.Equal(402, refused);
        Assert.StartsWith("budget exceeded", body.GetProperty("error").GetString());
        Assert.True(await t.ScalarAsync("select count(*) from agent_tool_calls where principal_id = @p and tool = 'rest:GET /api/messages' and status = 'budget_blocked'", ("p", agent.Id)) >= 1);

        // Exempt: GET /api/me (free) and releasing a claim. done is refused, even disguised by a second, differently cased key.
        Assert.Equal(200, A1.Read(await app.Api.Me(A1.Request(agent.Handle, path: "/api/me"))).Status);
        Assert.Equal(0, await t.ScalarAsync("select coalesce(sum(cost_usd), 0)::bigint * 1000 from agent_metered_daily where principal_id = @p and tool = 'rest:GET /api/me'", ("p", agent.Id)));
        await t.Board.ClaimAsync(agent, q.Id, null, Ct);
        Assert.Equal(402, A1.Read(await app.Api.Claim(A1.Request(agent.Handle, "POST", new { op = "done" }, path: $"/api/claims/{q.Id}"), q.Id.ToString())).Status);
        var sneaky = JsonDocument.Parse("""{"op":"release","OP":"done"}""").RootElement;
        Assert.Equal(402, A1.Read(await app.Api.Claim(A1.Request(agent.Handle, "POST", sneaky, path: $"/api/claims/{q.Id}"), q.Id.ToString())).Status);
        Assert.Equal(200, A1.Read(await app.Api.Claim(A1.Request(agent.Handle, "POST", new { op = "release" }, path: $"/api/claims/{q.Id}"), q.Id.ToString())).Status);

        // People are never budgeted or traced on REST.
        Assert.Equal(200, A1.Read(await app.Api.Messages(A1.Request("analyst", path: "/api/messages", query: "?channel=triage"))).Status);
        Assert.Equal(0, await t.ScalarAsync("select count(*) from agent_tool_calls where principal_id = @p and tool like 'rest:%'", ("p", admin.Id)));
    }

    [DbFact]
    public async Task Concurrent_evaluations_block_once_notify_once_and_never_flip()
    {
        var app = A1.Build(t, new Policy());
        var agent = await NewAgent();
        var admin = await t.As("analyst");
        await app.Budgets.SetBudgetAsync(admin, agent.Handle, new BudgetInput(DailyUsd: 0.05, Reason: "integration test budget"), Ct);

        // Forty metered calls race (each re-evaluates); spend crosses $0.05 part-way through.
        await Task.WhenAll(Enumerable.Range(0, 40).Select(_ => Task.Run(() => app.Budgets.MeterAsync(agent.Id, "read_feed", false, Ct), Ct)));
        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Task.Run(() => app.Budgets.EvaluateAsync(agent.Id, Ct), Ct)));

        Assert.True((await app.Budgets.EvaluateAsync(agent.Id, Ct))!.Blocked);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'agent.budget_exceeded' and subject = @h", ("h", agent.Handle)));
        Assert.Equal(0, await t.ScalarAsync("select count(*) from audit_log where event = 'agent.budget_cleared' and subject = @h", ("h", agent.Handle)));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from messages where payload->>'state' = 'agent_budget_exceeded' and payload->>'handle' = @h", ("h", agent.Handle)));

        // An admin top-up clears it; going over again in the same period blocks again but doesn't notify again.
        await app.Budgets.TopUpAsync(admin, agent.Handle, new TopupInput(Usd: 0.5, Hours: 1, Reason: "integration test top-up"), Ct);
        Assert.False((await app.Budgets.EvaluateAsync(agent.Id, Ct))!.Blocked);
        await app.Budgets.SetBudgetAsync(admin, agent.Handle, new BudgetInput(DailyUsd: 0.01, Reason: "integration test lower"), Ct);
        await using (var c = t.Db.Command("delete from agent_budget_topups where principal_id = @p").With("p", agent.Id)) await c.ExecuteNonQueryAsync(Ct);
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => Task.Run(() => app.Budgets.EvaluateAsync(agent.Id, Ct), Ct)));
        Assert.True((await app.Budgets.EvaluateAsync(agent.Id, Ct))!.Blocked);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from messages where payload->>'state' = 'agent_budget_exceeded' and payload->>'handle' = @h", ("h", agent.Handle)));
    }

    [DbFact]
    public async Task Usage_reports_are_validated_deduplicated_and_priced_by_the_board()
    {
        var app = A1.Build(t, new Policy());
        var tools = A1.Tools(app);
        var agent = await NewAgent();

        Assert.Contains("error", await tools.ReportUsage(A1.Mcp("report_usage", agent.Handle, Usage(-5, 10))));
        Assert.Contains("error", await tools.ReportUsage(A1.Mcp("report_usage", agent.Handle, Usage(60_000_000, 10))));
        Assert.Contains("error", await tools.ReportUsage(A1.Mcp("report_usage", agent.Handle, Usage(0, 0))));

        // The agent's own cost claim is ignored for a known model: the board's price table wins.
        var args = Usage(1_000_000, 0, requestId: "dup");
        args["cost_usd"] = 0.0001;
        var first = JsonDocument.Parse(await tools.ReportUsage(A1.Mcp("report_usage", agent.Handle, args))).RootElement;
        Assert.Equal("price_table", first.GetProperty("cost_source").GetString());
        Assert.Equal(4.0, first.GetProperty("cost_usd").GetDouble(), 3);
        var again = JsonDocument.Parse(await tools.ReportUsage(A1.Mcp("report_usage", agent.Handle, args))).RootElement;
        Assert.True(again.GetProperty("duplicate").GetBoolean());
        Assert.Equal(1, await t.ScalarAsync("select count(*) from agent_usage where principal_id = @p", ("p", agent.Id)));

        // People can't report usage.
        Assert.Contains("only agents", await tools.ReportUsage(A1.Mcp("report_usage", "analyst", Usage(10, 10))));
    }

    [DbFact]
    public async Task Budgets_are_human_admin_only()
    {
        var app = A1.Build(t, new Policy());
        var agent = await NewAgent();
        var ex = await Assert.ThrowsAsync<BoardException>(() => app.Budgets.SetBudgetAsync(agent, agent.Handle, new BudgetInput(DailyUsd: 1000, Reason: "raise my own budget"), Ct));
        Assert.Equal(403, ex.Status);
        var reader = await t.As("reader");
        Assert.Equal(403, (await Assert.ThrowsAsync<BoardException>(() => app.Budgets.SetBudgetAsync(reader, agent.Handle, new BudgetInput(DailyUsd: 1, Reason: "not an admin"), Ct))).Status);
    }

    [DbFact]
    public async Task Resolution_with_a_different_classification_records_one_overturn()
    {
        var app = A1.Build(t, new Policy());
        var agent = await NewAgent();
        var graphId = Random.Shared.Next(100_000, 999_999).ToString();
        await app.Ingest.UpsertAsync(TestBoard.SampleIncident(graphId), Ct);
        var incident = (await t.Board.ResolveIncidentAsync(graphId, Ct))!.Value;
        var verdict = await t.Board.PostAsync(agent, new PostInput("incidents", "Looks malicious.", "verdict",
            A1.El(new { classification = "truePositive", confidence = 0.8 }), Incident: graphId), ct: Ct);

        // Defender resolves it as a false positive: the sync records an overturn, once.
        var resolved = TestBoard.SampleIncident(graphId);
        var node = System.Text.Json.Nodes.JsonNode.Parse(resolved.GetRawText())!.AsObject();
        node["status"] = "resolved";
        node["classification"] = "falsePositive";
        var el = JsonSerializer.SerializeToElement(node);
        await app.Ingest.UpsertAsync(el, Ct);
        await app.Ingest.UpsertAsync(el, Ct);

        Assert.Equal(1, await t.ScalarAsync("select count(*) from agent_feedback where message_id = @m and source = 'resolution' and verdict = 'incorrect' and corrected_classification = 'falsePositive'", ("m", verdict.Id)));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'agent.verdict_overturned' and subject = @m", ("m", verdict.Id.ToString())));

        // The agent sees it through get_agent_feedback.
        var mine = await app.Feedback.ForAgentAsync(agent, new AgentFeedbackQuery(IncorrectOnly: true), Ct);
        Assert.Contains(mine.Items, i => i.MessageId == verdict.Id && i.CorrectedClassification == "falsePositive");
        _ = incident;
    }

    [DbFact]
    public async Task Same_classification_resolution_confirms_the_verdict()
    {
        var app = A1.Build(t, new Policy());
        var agent = await NewAgent();
        var graphId = Random.Shared.Next(100_000, 999_999).ToString();
        await app.Ingest.UpsertAsync(TestBoard.SampleIncident(graphId), Ct);
        var incident = (await t.Board.ResolveIncidentAsync(graphId, Ct))!.Value;
        var verdict = await t.Board.PostAsync(agent, new PostInput("incidents", "Benign.", "verdict",
            A1.El(new { classification = "falsePositive", confidence = 0.9 }), Incident: graphId), ct: Ct);
        Assert.Equal("correct", await app.Feedback.RecordResolutionAsync(incident, "falsePositive", "update_incident", Ct));
        Assert.Null(await app.Feedback.RecordResolutionAsync(incident, "falsePositive", "sync", Ct)); // already compared
        Assert.Equal(1, await t.ScalarAsync("select count(*) from agent_feedback where message_id = @m and verdict = 'correct'", ("m", verdict.Id)));
    }

    [DbFact]
    public async Task Only_people_give_feedback_and_only_on_agent_typed_messages()
    {
        var app = A1.Build(t, new Policy());
        var agent = await NewAgent();
        var finding = await t.Board.PostAsync(agent, new PostInput("triage", "Seen on 3 hosts.", "finding", A1.El(new { confidence = 0.6 })), ct: Ct);
        var human = await t.As("analyst");
        var fb = await app.Feedback.GiveAsync(human, finding.Id, new FeedbackInput("incorrect", "Only one host; the others were the proxy."), Ct);
        Assert.Equal(1, fb.Incorrect);
        Assert.Equal("incorrect", fb.Mine);
        // Changing your mind replaces your feedback.
        fb = await app.Feedback.GiveAsync(human, finding.Id, new FeedbackInput("correct"), Ct);
        Assert.Equal((1, 0), (fb.Correct, fb.Incorrect));

        Assert.Equal(403, (await Assert.ThrowsAsync<BoardException>(() => app.Feedback.GiveAsync(agent, finding.Id, new FeedbackInput("correct"), Ct))).Status);
        var chat = await t.Board.PostAsync(agent, new PostInput("general", "hello"), ct: Ct);
        await Assert.ThrowsAsync<BoardException>(() => app.Feedback.GiveAsync(human, chat.Id, new FeedbackInput("correct"), Ct));
    }

    [DbFact]
    public async Task Tool_calls_are_traced_with_redacted_arguments_and_kql_and_linked_to_the_claim()
    {
        var app = A1.Build(t, new Policy());
        var tools = A1.Tools(app);
        var agent = await NewAgent();
        var admin = await t.As("analyst");
        var q = await t.Board.PostAsync(admin, new PostInput("incidents", "Check the download", "question", Incident: TestBoard.IncidentGraphId), ct: Ct);
        await tools.ClaimMessage(A1.Mcp("claim_message", agent.Handle, new() { ["message_id"] = q.Id.ToString() }));
        await tools.RunHuntingQuery(A1.Mcp("run_hunting_query", agent.Handle, new() { ["query"] = "DeviceProcessEvents | where DeviceName == 'ws-042' | take 10" }));
        // A post carrying a secret is refused and traced without the secret.
        var secret = "ghp_" + new string('A', 36);
        var refused = await tools.PostMessage(A1.Mcp("post_message", agent.Handle, new() { ["channel"] = "triage", ["body"] = $"token {secret}" }));
        Assert.Contains("refusing", refused);

        var calls = await app.Trace.ForIncidentAsync(t.IncidentId, Ct);
        var hunt = Assert.Single(calls, c => c.Tool == "run_hunting_query" && c.Handle == agent.Handle);
        Assert.Equal(q.Id, hunt.ClaimMessageId);
        Assert.Contains("DeviceProcessEvents", hunt.Kql);
        Assert.Equal(0, await t.ScalarAsync("select count(*) from agent_tool_calls where principal_id = @p and (args_summary::text like '%ghp_%' or coalesce(error, '') like '%ghp_%')", ("p", agent.Id)));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from agent_tool_calls where principal_id = @p and status = 'secret_blocked'", ("p", agent.Id)));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where actor_id = @p and event = 'agent.secret_blocked'", ("p", agent.Id)));

        // Metered board-side, whatever the agent reports.
        Assert.True(await t.ScalarAsync("select coalesce(sum(calls), 0) from agent_metered_daily where principal_id = @p", ("p", agent.Id)) >= 3);
        // Retention deletes old rows.
        await t.OwnerExecAsync($"update agent_tool_calls set created_at = now() - interval '40 days' where principal_id = '{agent.Id}'");
        Assert.True(await app.Trace.PurgeAsync(30, Ct) >= 3);
    }

    [DbFact]
    public async Task Risk_scores_are_stored_and_readable_through_the_risk_source()
    {
        var app = A1.Build(t, new Policy());
        var agent = await NewAgent();
        var sys = new SystemPrincipal(t.Db);
        var store = new ObservabilitySettingsStore(t.Db, t.Audit);
        var risk = new AgentRisk(t.Db, t.Audit, t.Board, sys, new Participants(t.Db, t.Audit, t.Board, sys), store);
        // Two secret-leak blocks: 30 points.
        await t.Audit.WriteAsync(agent.Id, "agent.secret_blocked", "post_message", null, Ct);
        await t.Audit.WriteAsync(agent.Id, "agent.secret_blocked", "post_message", null, Ct);
        await risk.RecomputeAllAsync(Ct);
        IAgentRiskSource source = risk;
        var score = await source.GetScoreAsync(agent.Id, Ct);
        Assert.NotNull(score);
        Assert.Equal(30, score!.Score);
        Assert.Contains(score.Factors, f => f.Key == "secret_leak_blocks" && f.Points == 30);
        Assert.Null(await source.GetScoreAsync((await t.As("analyst")).Id, Ct));
        _ = app;
    }
}
