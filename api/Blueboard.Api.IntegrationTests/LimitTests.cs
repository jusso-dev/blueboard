using Blueboard.Contracts;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Mcp;
using Microsoft.Azure.Functions.Worker.Extensions.Mcp;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Issue #5: per-principal token buckets in Postgres, REST 429 + Retry-After, MCP errors, the per-incident cap.</summary>
public sealed class LimitTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static Policy WithAgent(LimitSet agent, int pendingCap = 10) => new() { Limits = new Limits { Agent = agent, PendingActionsPerIncident = pendingCap } };

    /// <summary>A principal of its own per test, so buckets never carry over between tests.</summary>
    private async Task<Principal> NewPrincipal(string kind, string[]? roles = null)
    {
        var handle = $"{kind}-{Guid.NewGuid():N}"[..20];
        await using (var c = t.Db.Command("insert into principals (handle, display_name, kind, roles) values (@h, @h, @k, @r)")
                         .With("h", handle).With("k", kind).With("r", roles ?? ["poster", "hunter", "requester"]))
            await c.ExecuteNonQueryAsync(Ct);
        return await t.As(handle);
    }

    private static async Task<(int Ok, int Limited, BoardException? Last)> Burst(int n, Func<Task> call)
    {
        var (ok, limited) = (0, 0);
        BoardException? last = null;
        for (var i = 0; i < n; i++)
        {
            try { await call(); ok++; }
            catch (BoardException ex) when (ex.Status == 429) { limited++; last = ex; }
        }
        return (ok, limited, last);
    }

    [DbFact]
    public async Task Hunt_limit_stops_the_graph_call_and_mcp_says_when_to_retry()
    {
        var app = A1.Build(t, WithAgent(new LimitSet { Hunt = new(3, 60) }), limited: true);
        var agent = await NewPrincipal("agent");
        var tools = new BoardTools(app.Auth, app.Board, app.Broker, app.Enrich, app.Hooks, app.Policy, app.Playbooks, app.Intel, NullLogger<BoardTools>.Instance);
        var ctx = new ToolInvocationContext
        {
            Name = "run_hunting_query",
            Transport = new HttpTransport("http") { Headers = new() { ["Authorization"] = $"Bearer dev:{agent.Handle}" } },
            Arguments = new Dictionary<string, object> { ["query"] = "DeviceEvents | take 1" },
        };

        for (var i = 0; i < 3; i++) Assert.DoesNotContain("error", await tools.RunHuntingQuery(ctx));
        Assert.Equal(3, app.Microsoft.Calls);

        var refused = await tools.RunHuntingQuery(ctx);
        Assert.Matches(@"^error: rate limited: run_hunting_query, retry in \d+s$", refused);
        Assert.Equal(3, app.Microsoft.Calls); // no Graph call was made for the refused query
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'limit.hit' and actor_id = @p and detail->>'bucket' = 'hunt'", ("p", agent.Id)));
    }

    [DbFact]
    public async Task Rest_returns_429_with_retry_after()
    {
        var app = A1.Build(t, WithAgent(new LimitSet { Post = new(2, 60) }), limited: true);
        var agent = await NewPrincipal("agent");
        for (var i = 0; i < 2; i++)
            Assert.Equal(200, A1.Read(await app.Api.Post(A1.Request(agent.Handle, "POST", new { channel = "general", body = $"post {i}" }))).Status);

        var req = A1.Request(agent.Handle, "POST", new { channel = "general", body = "one too many" });
        var (status, body) = A1.Read(await app.Api.Post(req));
        Assert.Equal(429, status);
        Assert.Matches(@"^rate limited: post, retry in \d+s$", body.GetProperty("error").GetString());
        Assert.True(int.Parse(req.HttpContext.Response.Headers.RetryAfter.ToString()) is >= 1 and <= 30);
    }

    [DbFact]
    public async Task Limits_hold_across_two_instances_sharing_one_database()
    {
        var policy = WithAgent(new LimitSet { Post = new(20, 3600) });
        // Two independent "instances": separate connection pools and service graphs, one database.
        await using var db2 = new Db(t.Settings);
        var a = A1.Build(t, policy, limited: true);
        var b = A1.Build(t, policy, db2, limited: true);
        var agent = await NewPrincipal("agent");

        var results = await Task.WhenAll(Enumerable.Range(0, 60).Select(i => Task.Run(async () =>
        {
            try { await (i % 2 == 0 ? a : b).Board.PostAsync(agent, new PostInput("general", $"two instances {i}"), ct: Ct); return true; }
            catch (BoardException ex) when (ex.Status == 429) { return false; }
        }, Ct)));
        Assert.Equal(20, results.Count(r => r));
        Assert.Equal(20, await t.ScalarAsync("select count(*) from messages where author_id = @p", ("p", agent.Id)));
    }

    /// <summary>The issue's load test: 1,000 posts in about 10 seconds from one principal store at most the configured number.</summary>
    [DbFact]
    public async Task Thousand_posts_from_one_principal_store_at_most_the_limit()
    {
        var app = A1.Build(t, WithAgent(new LimitSet { Post = new(60, 60) }), limited: true);
        var agent = await NewPrincipal("agent");
        var started = DateTimeOffset.UtcNow;
        // 10 concurrent senders × 100 posts, paced to finish in about 10 seconds. Fewer senders than the pool has
        // connections (20), so a slow CI database queues requests instead of timing out on the pool.
        var perWorker = await Task.WhenAll(Enumerable.Range(0, 10).Select(w => Task.Run(async () =>
        {
            var ok = new List<bool>();
            for (var n = 0; n < 100; n++)
            {
                var due = started.AddMilliseconds(n * 100);
                if (due > DateTimeOffset.UtcNow) await Task.Delay(due - DateTimeOffset.UtcNow, Ct);
                try { await app.Board.PostAsync(agent, new PostInput("general", $"flood {w}-{n}"), ct: Ct); ok.Add(true); }
                catch (BoardException ex) when (ex.Status == 429) { ok.Add(false); }
            }
            return ok;
        }, Ct)));
        var results = perWorker.SelectMany(x => x).ToList();
        Assert.Equal(1000, results.Count);
        var elapsed = (DateTimeOffset.UtcNow - started).TotalSeconds;
        var stored = await t.ScalarAsync("select count(*) from messages where author_id = @p", ("p", agent.Id));
        // 60 to start with, plus at most one refill per second while the flood ran.
        Assert.InRange(stored, 60, 60 + (long)Math.Ceiling(elapsed) + 1);
        Assert.Equal(stored, results.Count(r => r));
        // Audited once per minute per bucket, not once per refused call.
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'limit.hit' and actor_id = @p", ("p", agent.Id)));
    }

    [DbFact]
    public async Task Humans_get_higher_defaults_than_agents()
    {
        var app = A1.Build(t, new Policy(), limited: true);
        var agent = await NewPrincipal("agent");
        var human = await NewPrincipal("human");
        var (agentOk, _, last) = await Burst(15, () => app.Enrich.HuntAsync(agent, "DeviceEvents | take 1", null, Ct));
        var (humanOk, humanLimited, _) = await Burst(15, () => app.Enrich.HuntAsync(human, "DeviceEvents | take 1", null, Ct));
        Assert.Equal(10, agentOk);
        Assert.Equal("hunt", last!.Bucket);
        Assert.Equal(15, humanOk);
        Assert.Equal(0, humanLimited);
    }

    [DbFact]
    public async Task Lookups_claims_and_action_requests_are_limited()
    {
        var app = A1.Build(t, WithAgent(new LimitSet { Lookup = new(2, 60), Claim = new(1, 60), ActionRequest = new(2, 600) }), limited: true);
        var agent = await NewPrincipal("agent");
        Assert.Equal((2, 1), (await Burst(3, () => app.Enrich.LookupAsync(agent, "file", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", Ct))) is var l ? (l.Ok, l.Limited) : default);

        var q1 = await app.Board.PostAsync(await t.As("analyst"), new PostInput("intel", "first question to claim", "question"), ct: Ct);
        var q2 = await app.Board.PostAsync(await t.As("analyst"), new PostInput("intel", "second question to claim", "question"), ct: Ct);
        await app.Board.ClaimAsync(agent, q1.Id, ct: Ct);
        Assert.Equal(429, (await Assert.ThrowsAsync<BoardException>(() => app.Board.ClaimAsync(agent, q2.Id, ct: Ct))).Status);

        var r = await Burst(3, () => app.Broker.RequestAsync(agent, A1.Isolate(), Ct));
        Assert.Equal((2, 1), (r.Ok, r.Limited));
        Assert.Equal("action_request", r.Last!.Bucket);
        Assert.InRange(r.Last.RetryAfterSeconds!.Value, 1, 300);
    }

    [DbFact]
    public async Task Pending_actions_per_incident_are_capped()
    {
        await using (var c = t.Db.Command("update actions set status = 'denied' where status = any(@s)").With("s", ActionStatus.Open))
            await c.ExecuteNonQueryAsync(Ct);
        var app = A1.Build(t, new Policy { Limits = new Limits { PendingActionsPerIncident = 3, Human = new LimitSet { ActionRequest = new(100, 60) } } }, limited: true);
        var human = await NewPrincipal("human", ["poster", "requester"]);
        for (var i = 0; i < 3; i++) await app.Broker.RequestAsync(human, A1.Isolate(), Ct);
        var ex = await Assert.ThrowsAsync<BoardException>(() => app.Broker.RequestAsync(human, A1.Isolate(), Ct));
        Assert.Equal(429, ex.Status);
        Assert.Contains("already has 3 actions waiting for approval", ex.Message);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'limit.hit' and actor_id = @p and detail->>'bucket' = 'pending_actions_per_incident'", ("p", human.Id)));

        // Auto-approved requests aren't pending, so they still go through.
        var scan = await app.Broker.RequestAsync(human, new ActionRequest("run_av_scan", A1.El(new { machine_id = TestBoard.Device }),
            "Scan while the isolation requests wait for a decision.", TestBoard.IncidentGraphId), Ct);
        Assert.Equal("succeeded", scan.Status);
    }

    [DbFact]
    public async Task System_principal_is_never_limited()
    {
        var app = A1.Build(t, WithAgent(new LimitSet { Post = new(1, 3600) }, pendingCap: 1), limited: true);
        var sys = await new SystemPrincipal(t.Db).GetAsync(Ct);
        for (var i = 0; i < 5; i++) await app.Limiter.TakeAsync(sys, "post", Ct);
        for (var i = 0; i < 5; i++) await app.Board.PostAsync(sys, new PostInput("general", $"system post {i}"), system: true, ct: Ct);
        Assert.Equal(0, await t.ScalarAsync("select count(*) from rate_buckets where principal_id = @p", ("p", sys.Id)));
    }

    [DbFact]
    public async Task Usage_reports_buckets_per_principal()
    {
        var app = A1.Build(t, WithAgent(new LimitSet { Hunt = new(10, 60) }), limited: true);
        var agent = await NewPrincipal("agent");
        for (var i = 0; i < 4; i++) await app.Enrich.HuntAsync(agent, "DeviceEvents | take 1", null, Ct);
        var usage = await app.Limiter.UsageAsync(agent.Id, Ct);
        var hunt = Assert.Single(usage);
        Assert.Equal(("hunt", 10, 60), (hunt.Bucket, hunt.Capacity, hunt.PerSeconds));
        Assert.InRange(hunt.Available, 6, 6.5);
        Assert.Contains(await app.Limiter.UsageAsync(null, Ct), u => u.Handle == agent.Handle);
    }
}
