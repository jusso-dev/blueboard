using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Intel;
using Blueboard.Contracts;
using Npgsql;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>
/// WS2 on a real database: a back-test is stored by the board, create_detection_rule binds to it by query hash, the
/// dry run shows the exact tagged rule, disable only targets board-created rules, and back-tests are append-only.
/// </summary>
public sealed class DetectionTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private const string Query = "DeviceProcessEvents | where ProcessCommandLine has 'EncodedCommand' | project Timestamp, DeviceName";

    private (DetectionService Detections, Broker Broker) Build(Policy? policy = null)
    {
        var ms = new MsClient(new HttpClient(new Hunting()), new Token());
        var audit = new Audit(t.Db);
        var board = new BoardService(t.Db, audit, t.Settings);
        return (new DetectionService(t.Db, audit, ms, t.Settings), new Broker(t.Db, audit, board, ms, t.Settings, policy ?? new Policy(), new SystemPrincipal(t.Db)));
    }

    private static ActionRequest Rule(Guid backtest, string query = Query) =>
        new("create_detection_rule", JsonSerializer.SerializeToElement(new { target = "defender", name = "Encoded PowerShell", query, backtest_id = backtest, severity = "high" }),
            "Emerging threat: encoded PowerShell downloads seen on two incidents this week; back-test shows low volume.");

    [DbFact]
    public async Task Backtest_is_stored_and_a_bound_rule_waits_for_a_person_then_dry_runs_tagged()
    {
        var (detections, broker) = Build(new Policy { AutoApprove = ["create_detection_rule"] });
        var bt = await detections.BacktestAsync(await t.As("agent"), new BacktestInput(Query, "defender", 14, ["DeviceName"]), Ct);
        Assert.Equal(3, bt.TotalHits);
        Assert.Equal(DetectionService.QueryHash(Query), bt.QuerySha256);
        Assert.Equal(2, bt.DistinctEntities[0].Distinct);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from detection_backtests where id = @id", ("id", bt.BacktestId)));

        var row = await broker.RequestAsync(await t.As("agent"), Rule(bt.BacktestId), Ct);
        Assert.Equal("pending_approval", row.Status); // never auto, even when listed
        Assert.Contains(row.PolicyNotes, n => n.Contains("3 hits"));

        var done = await broker.DecideAsync(await t.As("analyst"), row.Id, "approve", null, Ct);
        Assert.Equal("succeeded", done.Status);
        var request = done.Result!.Value.GetProperty("request").GetProperty("requests")[0];
        Assert.Equal("/v1.0/security/rules/detectionRules", request.GetProperty("path").GetString());
        Assert.StartsWith("[blueboard] ", request.GetProperty("body").GetProperty("displayName").GetString());
        Assert.Contains(row.Id.ToString(), request.GetProperty("body").GetProperty("description").GetString());
    }

    [DbFact]
    public async Task Reverting_a_dry_run_rule_fails_clearly()
    {
        var (detections, broker) = Build();
        var bt = await detections.BacktestAsync(await t.As("agent"), new BacktestInput(Query, "defender", 14), Ct);
        var row = await broker.RequestAsync(await t.As("agent"), Rule(bt.BacktestId), Ct);
        var done = await broker.DecideAsync(await t.As("analyst"), row.Id, "approve", null, Ct);
        Assert.True(done.Result!.Value.GetProperty("dry_run").GetBoolean());

        var after = await broker.RevertOpAsync(await t.As("analyst2"), row.Id, new("now"), Ct);
        Assert.Equal("failed", after.RevertState);
        Assert.Null(after.RevertActionId);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'action.revert_failed' and subject = @id and detail->>'reason' like '%dry run%'", ("id", row.Id.ToString())));
    }

    [DbFact]
    public async Task Rule_whose_query_differs_from_the_backtest_is_rejected()
    {
        var (detections, broker) = Build();
        var bt = await detections.BacktestAsync(await t.As("agent"), new BacktestInput(Query, "defender", 14), Ct);
        var row = await broker.RequestAsync(await t.As("agent"), Rule(bt.BacktestId, Query + " | where DeviceName != 'x'"), Ct);
        Assert.Equal("rejected", row.Status);
        Assert.Contains("is not the query back-tested", row.PolicyNotes[0]);
    }

    [DbFact]
    public async Task Disable_only_targets_succeeded_rules_this_board_created()
    {
        var (detections, broker) = Build();
        var disable = new ActionRequest("disable_detection_rule", JsonSerializer.SerializeToElement(new { rule_action_id = Guid.NewGuid() }),
            "The rule floods the queue with false positives on build servers; disable it.");
        Assert.Equal("rejected", (await broker.RequestAsync(await t.As("agent"), disable, Ct)).Status);

        var bt = await detections.BacktestAsync(await t.As("agent"), new BacktestInput(Query, "defender", 14), Ct);
        var created = await broker.RequestAsync(await t.As("agent"), Rule(bt.BacktestId), Ct);
        await broker.DecideAsync(await t.As("analyst"), created.Id, "approve", null, Ct);
        var row = await broker.RequestAsync(await t.As("agent"), disable with { Params = JsonSerializer.SerializeToElement(new { rule_action_id = created.Id }) }, Ct);
        Assert.Equal("pending_approval", row.Status);
        var done = await broker.DecideAsync(await t.As("analyst2"), row.Id, "approve", null, Ct);
        Assert.Equal($"/v1.0/security/rules/detectionRules/blueboard-{created.Id:N}",
            done.Result!.Value.GetProperty("request").GetProperty("requests")[0].GetProperty("path").GetString());
    }

    [DbFact]
    public async Task Backtests_are_append_only_for_the_runtime_role()
    {
        var (detections, _) = Build();
        var bt = await detections.BacktestAsync(await t.As("agent"), new BacktestInput(Query, "defender", 7), Ct);
        await using var cmd = t.Db.Command("update detection_backtests set total_hits = 0 where id = @id").With("id", bt.BacktestId);
        var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync(Ct));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, ex.SqlState);
    }

    /// <summary>Advanced hunting with three hits on two devices for any query.</summary>
    private sealed class Hunting : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var now = DateTimeOffset.UtcNow;
            var body = JsonSerializer.Serialize(new
            {
                schema = Array.Empty<object>(),
                results = new[]
                {
                    new { Timestamp = now.AddDays(-1).ToString("O"), DeviceName = "ws-1" },
                    new { Timestamp = now.AddDays(-1).ToString("O"), DeviceName = "ws-2" },
                    new { Timestamp = now.AddDays(-3).ToString("O"), DeviceName = "ws-1" },
                },
            });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private sealed class Token : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => new("test-token", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => new(GetToken(requestContext, cancellationToken));
    }
    [DbFact]
    public async Task Reading_a_stored_backtest_needs_board_hunt()
    {
        var (detections, _) = Build();
        var bt = await detections.BacktestAsync(await t.As("agent"), new BacktestInput(Query, "defender", 14, ["DeviceName"]), Ct);
        var api = new Http.BoardApi(new Http.Endpoint(new Auth.Authenticator(t.Settings, new Auth.TokenValidator(t.Settings), t.Db, t.Audit),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Http.Endpoint>.Instance),
            t.Board, t.Search, t.Reporting, t.Broker, null!, null!, null!, t.Db, t.Policy, t.Incidents, t.Runner, t.Playbooks, null!, t.Audit, null!, null!, null!,
            detections: detections);
        // "reader" has Board.Post only: the query and sample rows are hunting data, so it is refused.
        Assert.Equal(403, A1.Read(await api.BacktestGet(A1.Request("reader"), bt.BacktestId.ToString())).Status);
        var (ok, body) = A1.Read(await api.BacktestGet(A1.Request("analyst"), bt.BacktestId.ToString()));
        Assert.Equal(200, ok);
        Assert.Equal(Query, body.GetProperty("query").GetString());
    }
}
