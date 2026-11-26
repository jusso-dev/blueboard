using Blueboard.Contracts;
using System.Collections.Concurrent;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

public sealed class BoardTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [DbFact]
    public async Task Replies_must_target_the_root_in_the_same_channel()
    {
        var a = await t.As("analyst");
        var root = await t.Board.PostAsync(a, new PostInput("triage", "root question for thread rules", "question"), ct: Ct);
        var reply = await t.Board.PostAsync(a, new PostInput("triage", "a reply", "chat", null, root.Id), ct: Ct);
        await Assert.ThrowsAsync<BoardException>(() => t.Board.PostAsync(a, new PostInput("triage", "reply to reply", "chat", null, reply.Id), ct: Ct));
        await Assert.ThrowsAsync<BoardException>(() => t.Board.PostAsync(a, new PostInput("general", "wrong channel", "chat", null, root.Id), ct: Ct));
    }

    [DbFact]
    public async Task Thread_roots_carry_last_reply_and_the_latest_repliers()
    {
        var a = await t.As("analyst");
        var root = await t.Board.PostAsync(a, new PostInput("triage", "root for the replies row"), ct: Ct);
        Assert.Equal((0, null), (root.ReplyCount, root.LastReplyAt));
        Assert.Empty(root.ReplyAuthors!);
        foreach (var who in new[] { "analyst2", "agent", "analyst2", "reader", "agent2", "analyst" })
            await t.Board.PostAsync(await t.As(who), new PostInput("triage", $"reply from {who}", "chat", null, root.Id), ct: Ct);

        var thread = await t.Board.GetThreadAsync(root.Id, Ct);
        Assert.Equal(6, thread.Root.ReplyCount);
        Assert.Equal(thread.Replies[^1].CreatedAt, thread.Root.LastReplyAt);
        // Distinct, most recent first, at most 4: analyst, agent2, reader, analyst2 (agent's only reply is older).
        Assert.Equal(["analyst", "agent2", "reader", "analyst2"], thread.Root.ReplyAuthors!.Select(x => x.Handle));
        Assert.Equal(("Agent Two", "agent"), (thread.Root.ReplyAuthors![1].DisplayName, thread.Root.ReplyAuthors[1].Kind));
        // The feed returns the same shape.
        var feed = await t.Board.ReadFeedAsync(new FeedQuery(Channel: "triage", RootsOnly: true, Limit: 5), Ct);
        Assert.Equal(thread.Root.ReplyAuthors!.Select(x => x.Handle), feed.Messages.Single(m => m.Id == root.Id).ReplyAuthors!.Select(x => x.Handle));
    }

    [DbFact]
    public async Task Outside_principals_cannot_post_board_types()
    {
        var agent = await t.As("agent");
        var ex = await Assert.ThrowsAsync<BoardException>(() => t.Board.PostAsync(agent, new PostInput("containment", "fake approval", "action_result"), ct: Ct));
        Assert.Contains("type must be one of", ex.Message);
    }

    [DbFact]
    public async Task Two_claimers_one_wins()
    {
        var q = await t.Board.PostAsync(await t.As("analyst"), new PostInput("intel", "who owns this ip?", "question"), ct: Ct);
        var a1 = await t.As("agent");
        var a2 = await t.As("agent2");
        var results = await Task.WhenAll(
            Try(() => t.Board.ClaimAsync(a1, q.Id, ct: Ct)),
            Try(() => t.Board.ClaimAsync(a2, q.Id, ct: Ct)));
        Assert.Equal(1, results.Count(r => r));
        static async Task<bool> Try(Func<Task> f) { try { await f(); return true; } catch (BoardException) { return false; } }
    }

    [DbFact]
    public async Task Expired_lease_can_be_reclaimed_and_settled()
    {
        var q = await t.Board.PostAsync(await t.As("analyst"), new PostInput("intel", "lease expiry check", "question"), ct: Ct);
        var a1 = await t.As("agent");
        var a2 = await t.As("agent2");
        await t.Board.ClaimAsync(a1, q.Id, 30, Ct);
        await using (var c = t.Db.Command("update messages set claim_expires_at = now() - interval '1 second' where id = @id").With("id", q.Id))
            await c.ExecuteNonQueryAsync(Ct);
        var reclaimed = await t.Board.ClaimAsync(a2, q.Id, ct: Ct);
        Assert.Equal("agent2", reclaimed.ClaimedBy);
        await Assert.ThrowsAsync<BoardException>(() => t.Board.SettleClaimAsync(a1, q.Id, "done", Ct));
        Assert.Equal("done", (await t.Board.SettleClaimAsync(a2, q.Id, "done", Ct)).ClaimState);
    }

    [DbFact]
    public async Task Search_finds_bodies_and_exact_ioc_values()
    {
        var a = await t.As("analyst");
        await t.Board.PostAsync(a, new PostInput("intel", "Beaconing observed from the workstation to a rare domain", "finding"), ct: Ct);
        await t.Board.PostAsync(a, new PostInput("intel", "indicator", "ioc",
            JsonSerializer.SerializeToElement(new { indicators = new[] { new { kind = "sha256", value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", verdict = "malicious" } } })), ct: Ct);
        var byWord = await t.Search.RunAsync(new SearchQuery(Q: "beacon"), Ct);
        Assert.Contains(byWord.Hits, h => h.Body.Contains("Beaconing"));
        var byHash = await t.Search.RunAsync(new SearchQuery(Q: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), Ct);
        Assert.Single(byHash.Hits);
    }

    /// <summary>
    /// Issue #4: concurrent writers and polling readers. Every reader must see every message exactly once, in seq order,
    /// even though seqs are allocated before commit. Without the feed lock this test drops messages.
    /// </summary>
    [DbFact]
    public async Task Feed_cursor_never_skips_under_concurrent_writes()
    {
        var writers = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => t.As("agent")));
        var start = (await t.Board.ReadFeedAsync(new FeedQuery(Limit: 1), Ct)).Cursor is { } c ? long.Parse(c) : 0;
        const int perWriter = 40;
        var stop = new CancellationTokenSource();
        var seen = Enumerable.Range(0, 3).Select(_ => new List<long>()).ToArray();

        var readers = seen.Select(list => Task.Run(async () =>
        {
            var cursor = start;
            while (true)
            {
                var done = stop.IsCancellationRequested;
                var page = await t.Board.ReadFeedAsync(new FeedQuery(Channel: "general", AfterSeq: cursor, Limit: 200), Ct);
                foreach (var m in page.Messages) list.Add(long.Parse(m.Seq));
                if (page.Cursor is { } next) cursor = long.Parse(next);
                if (done && page.Messages.Count == 0) break;
                await Task.Delay(5, Ct);
            }
        }, Ct)).ToArray();

        var written = new ConcurrentBag<long>();
        await Task.WhenAll(writers.Select((w, i) => Task.Run(async () =>
        {
            for (var n = 0; n < perWriter; n++)
                written.Add(long.Parse((await t.Board.PostAsync(w, new PostInput("general", $"w{i} m{n}"), ct: Ct)).Seq));
        }, Ct)));
        await stop.CancelAsync();
        await Task.WhenAll(readers);

        var expected = written.Order().ToList();
        foreach (var list in seen)
        {
            Assert.Equal(expected, list);
        }
    }

    [DbFact]
    public async Task Request_approve_execute_in_dry_run()
    {
        var agent = await t.As("agent");
        var broker = t.Broker;
        var a = await broker.RequestAsync(agent, new ActionRequest("isolate_device",
            JsonSerializer.SerializeToElement(new { machine_id = TestBoard.Device, isolation_type = "Selective" }),
            "Encoded PowerShell download from bad.example on this device; isolate to contain.", TestBoard.IncidentGraphId), Ct);
        Assert.Equal("pending_approval", a.Status);
        Assert.NotNull(a.RequestMessageId);

        await Assert.ThrowsAsync<BoardException>(() => broker.DecideAsync(agent, a.Id, "approve", null, Ct));
        var done = await broker.DecideAsync(await t.As("analyst"), a.Id, "approve", "contain it", Ct);
        Assert.Equal("succeeded", done.Status);
        Assert.True(done.Result!.Value.GetProperty("dry_run").GetBoolean());
        Assert.Equal(1, await t.ScalarAsync("select count(*) from messages where type = 'action_result' and payload->>'action_id' = @id", ("id", a.Id.ToString())));
    }

    [DbFact]
    public async Task Requester_cannot_approve_their_own_request()
    {
        var analyst = await t.As("analyst");
        var a = await t.Broker.RequestAsync(analyst, new ActionRequest("isolate_device",
            JsonSerializer.SerializeToElement(new { machine_id = TestBoard.Device }),
            "Requesting isolation myself to check the self-approval rule.", TestBoard.IncidentGraphId), Ct);
        var ex = await Assert.ThrowsAsync<BoardException>(() => t.Broker.DecideAsync(analyst, a.Id, "approve", null, Ct));
        Assert.Equal(403, ex.Status);
        Assert.Equal("pending_approval", (await t.Broker.GetAsync(a.Id, Ct))!.Status);
    }

    [DbFact]
    public async Task Recovery_marks_stale_running_actions_unknown_and_reposts_orphans()
    {
        var agent = await t.As("agent");
        var a = await t.Broker.RequestAsync(agent, new ActionRequest("isolate_device",
            JsonSerializer.SerializeToElement(new { machine_id = TestBoard.Device }),
            "Recovery sweep test: this request gets stuck in running.", TestBoard.IncidentGraphId), Ct);
        await using (var c = t.Db.Command("update actions set status = 'running', started_at = now() - interval '11 minutes' where id = @id").With("id", a.Id))
            await c.ExecuteNonQueryAsync(Ct);
        var (_, interrupted) = await t.Broker.RecoverAsync(Ct);
        Assert.True(interrupted >= 1);
        Assert.Equal("failed", (await t.Broker.GetAsync(a.Id, Ct))!.Status);
    }

    [DbFact]
    public async Task Action_request_rolls_back_with_its_message()
    {
        // A failure inside the request transaction (an unknown channel for the system post) must leave no action row.
        var before = await t.ScalarAsync("select count(*) from actions");
        await using (var c = t.Db.Command("update channels set name = 'containment-renamed' where name = 'containment'"))
            await c.ExecuteNonQueryAsync(Ct);
        try
        {
            await Assert.ThrowsAsync<BoardException>(() => t.Broker.RequestAsync(t.As("agent").Result, new ActionRequest("isolate_device",
                JsonSerializer.SerializeToElement(new { machine_id = TestBoard.Device }),
                "This request must roll back because its channel is missing.", TestBoard.IncidentGraphId), Ct));
            Assert.Equal(before, await t.ScalarAsync("select count(*) from actions"));
        }
        finally
        {
            await using var c = t.Db.Command("update channels set name = 'containment' where name = 'containment-renamed'");
            await c.ExecuteNonQueryAsync(Ct);
        }
    }
}
