using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Agents;
using Blueboard.Api.Data;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>
/// The requester-risk automation condition on a real database: the broker reads the requester's stored agent risk
/// (agent_risk, through IAgentRiskSource) and an unscored requester never auto-runs. The simulator path
/// (AssessAsync) and the real request agree.
/// </summary>
public sealed class CrossWorkstreamTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static Policy File(int maxRisk) => new()
    {
        Automation = new AutomationPolicy
        {
            ConditionalAutoAllowed = ["isolate_device"],
            Rules = new() { ["isolate_device"] = new AutoRuleSpec(0.9, ["high"], null, 10, 3, null, 60, false, maxRisk) },
        },
    };

    private async Task Sql(string sql, params (string, object?)[] args)
    {
        await using var c = t.Db.Command(sql);
        foreach (var (k, v) in args) c.With(k, v);
        await c.ExecuteNonQueryAsync(Ct);
    }

    private async Task<Broker> Fresh(Policy file)
    {
        await Sql("update actions set status = 'denied' where status = any(@s)", ("s", ActionStatus.Open));
        await Sql("update actions set auto_rule = null, revert_state = null where auto_rule is not null or revert_state is not null");
        await Sql("delete from messages where type = 'verdict'");
        await Sql("delete from agent_risk");
        var app = A1.Build(t, file);
        var sys = new SystemPrincipal(t.Db);
        var risk = new AgentRisk(t.Db, t.Audit, t.Board, sys, new Participants(t.Db, t.Audit, t.Board, sys), new ObservabilitySettingsStore(t.Db, t.Audit));
        var store = new PolicyStore(app.Db, t.Audit, app.Board, t.System, file, Blueboard.Api.Board.PlaybookSet.Empty);
        await t.Board.PostAsync(await t.As("analyst"), new PostInput("incidents", "verdict", "verdict",
            JsonSerializer.SerializeToElement(new { classification = "truePositive", confidence = 0.95 }), null, TestBoard.IncidentGraphId), ct: Ct);
        return new Broker(app.Db, t.Audit, app.Board, t.Ms, t.Settings, file, t.System, null, store, risk: risk);
    }

    private async Task Score(string handle, int score) =>
        await Sql("insert into agent_risk (principal_id, score) values (@p, @s) on conflict (principal_id) do update set score = excluded.score",
            ("p", (await t.As(handle)).Id), ("s", score));

    [DbFact]
    public async Task Unscored_requester_waits_for_a_person()
    {
        var broker = await Fresh(File(50));
        var agent = await t.As("agent");
        var preview = await broker.AssessAsync(agent, new PreviewRequest("isolate_device", A1.Isolate().Params, TestBoard.IncidentGraphId), Ct);
        Assert.Equal(Outcome.NeedsApproval, preview.Outcome);
        Assert.Contains(preview.Notes, n => n.Contains("has no agent risk score"));
        var a = await broker.RequestAsync(agent, A1.Isolate(), Ct);
        Assert.Equal("pending_approval", a.Status);
        Assert.Null(a.AutoRule);
    }

    [DbFact]
    public async Task Low_risk_requester_auto_runs_and_high_risk_requester_waits()
    {
        var broker = await Fresh(File(50));
        var agent = await t.As("agent");
        await Score("agent", 20);
        var ok = await broker.RequestAsync(agent, A1.Isolate(), Ct);
        Assert.Equal("succeeded", ok.Status);
        Assert.Equal("isolate_device@file", ok.AutoRule);

        broker = await Fresh(File(50));
        await Score("agent", 80);
        var preview = await broker.AssessAsync(agent, new PreviewRequest("isolate_device", A1.Isolate().Params, TestBoard.IncidentGraphId), Ct);
        Assert.Equal(Outcome.NeedsApproval, preview.Outcome);
        var held = await broker.RequestAsync(agent, A1.Isolate(), Ct);
        Assert.Equal("pending_approval", held.Status);
        Assert.Contains(held.PolicyNotes, n => n.Contains("agent risk score is 80"));
    }

    [DbFact]
    public async Task New_tools_from_every_feature_are_traced_and_metered_by_the_observer()
    {
        var app = A1.Build(t, new Policy());
        var tools = A1.Tools(app);
        var handle = $"xws-{Guid.NewGuid():N}"[..20];
        await Sql("insert into principals (handle, display_name, kind, roles) values (@h, @h, 'agent', @r)", ("h", handle), ("r", new[] { "poster", "hunter", "requester" }));
        var agent = await t.As(handle);
        // Timeline (incident views), Okta lookup (connectors: not configured here, still traced), back-test and
        // exposure (detections: not wired in this helper, still traced). Each must reach the McpObserver hook.
        await tools.GetIncidentTimeline(A1.Mcp("get_incident_timeline", handle, new() { ["incident"] = TestBoard.IncidentGraphId }));
        await tools.GetIncidentGraph(A1.Mcp("get_incident_graph", handle, new() { ["incident"] = TestBoard.IncidentGraphId }));
        await tools.LookupOktaUser(A1.Mcp("lookup_okta_user", handle, new() { ["user"] = "ana@contoso.com" }));
        await tools.BacktestDetection(A1.Mcp("backtest_detection", handle, new() { ["query"] = "DeviceProcessEvents | take 10" }));
        await tools.PrioritizeExposures(A1.Mcp("prioritize_exposures", handle));
        foreach (var tool in new[] { "get_incident_timeline", "get_incident_graph", "lookup_okta_user", "backtest_detection", "prioritize_exposures" })
            Assert.Equal(1, await t.ScalarAsync("select count(*) from agent_tool_calls where principal_id = @p and tool = @t", ("p", agent.Id), ("t", tool)));
        Assert.Equal(5, await t.ScalarAsync("select coalesce(sum(calls), 0) from agent_metered_daily where principal_id = @p", ("p", agent.Id)));
    }
}
