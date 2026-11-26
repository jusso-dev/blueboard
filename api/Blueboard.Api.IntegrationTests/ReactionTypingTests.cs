using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Slack-style reactions and typing indicators.</summary>
public sealed class ReactionTypingTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task<Message> Post(string who, string body, Guid? parent = null, string channel = "triage", string? incident = null) =>
        await t.Board.PostAsync(await t.As(who), new PostInput(channel, body, "chat", null, parent, incident), ct: Ct);

    [DbFact]
    public async Task Reactions_add_remove_count_and_are_idempotent()
    {
        var m = await Post("analyst", "contained the host, thanks all");
        var analyst2 = await t.As("analyst2");
        await t.Board.ReactAsync(await t.As("agent"), m.Id, "👀", false, Ct);
        await t.Board.ReactAsync(analyst2, m.Id, "👍", false, Ct);
        await t.Board.ReactAsync(analyst2, m.Id, "👍", false, Ct); // idempotent
        var rs = await t.Board.ReactAsync(await t.As("reader"), m.Id, "👍", false, Ct);

        // Ordered by first use; handles earliest first.
        Assert.Equal(["👀", "👍"], rs.Select(r => r.Emoji));
        Assert.Equal(1, rs[0].Count); Assert.Equal(["agent"], rs[0].Handles);
        Assert.Equal(2, rs[1].Count); Assert.Equal(["analyst2", "reader"], rs[1].Handles);

        rs = await t.Board.ReactAsync(analyst2, m.Id, "👍", true, Ct);
        Assert.Equal(1, rs[1].Count); Assert.Equal(["reader"], rs[1].Handles);
        rs = await t.Board.ReactAsync(analyst2, m.Id, "👍", true, Ct); // removing again changes nothing
        Assert.Equal(2, rs.Length);
        rs = await t.Board.ReactAsync(await t.As("agent"), m.Id, "👀", true, Ct);
        Assert.Equal(["👍"], rs.Select(r => r.Emoji));
    }

    [DbFact]
    public async Task Feed_thread_and_search_carry_reactions()
    {
        var root = await Post("analyst", "reactions on a thread root zebrafish");
        var reply = await Post("analyst2", "reply with a reaction", root.Id);
        await t.Board.ReactAsync(await t.As("agent"), root.Id, "✅", false, Ct);
        await t.Board.ReactAsync(await t.As("analyst"), reply.Id, "🙏", false, Ct);

        var thread = await t.Board.GetThreadAsync(root.Id, Ct);
        Assert.Equal("✅", Assert.Single(thread.Root.Reactions!).Emoji);
        Assert.Equal("🙏", Assert.Single(thread.Replies.Single().Reactions!).Emoji);
        var feed = await t.Board.ReadFeedAsync(new FeedQuery(Channel: "triage", Limit: 200), Ct);
        Assert.Equal("✅", feed.Messages.Single(m => m.Id == root.Id).Reactions![0].Emoji);
        var plain = await Post("analyst", "no reactions here");
        Assert.Null((await t.Board.GetAsync(plain.Id, Ct))!.Reactions);
        var hits = await t.Search.RunAsync(new SearchQuery(Q: "zebrafish"), Ct);
        Assert.Equal("✅", hits.Hits.Single(h => h.Id == root.Id).Reactions![0].Emoji);
    }

    [DbFact]
    public async Task Twenty_first_distinct_emoji_is_refused()
    {
        var m = await Post("analyst", "react to me a lot");
        var emoji = "😀 😁 😂 🤣 😃 😄 😅 😆 😉 😊 😋 😎 😍 😘 🥰 😗 😙 😚 🙂 🤗 🤩".Split(' ');
        var a = await t.As("analyst");
        foreach (var e in emoji[..20]) await t.Board.ReactAsync(a, m.Id, e, false, Ct);
        var ex = await Assert.ThrowsAsync<BoardException>(() => t.Board.ReactAsync(a, m.Id, emoji[20], false, Ct));
        Assert.Equal(400, ex.Status);
        // An emoji already on the message can still be added by someone else.
        var rs = await t.Board.ReactAsync(await t.As("analyst2"), m.Id, emoji[0], false, Ct);
        Assert.Equal(2, rs[0].Count);
    }

    [DbFact]
    public async Task Reaction_validation_and_missing_message()
    {
        var m = await Post("analyst", "validate my reactions");
        var a = await t.As("analyst");
        Assert.Equal(400, (await Assert.ThrowsAsync<BoardException>(() => t.Board.ReactAsync(a, m.Id, "+1", false, Ct))).Status);
        Assert.Equal(400, (await Assert.ThrowsAsync<BoardException>(() => t.Board.ReactAsync(a, m.Id, "👍👍", false, Ct))).Status);
        Assert.Equal(404, (await Assert.ThrowsAsync<BoardException>(() => t.Board.ReactAsync(a, Guid.NewGuid(), "👍", false, Ct))).Status);
        Assert.Equal(0, await t.ScalarAsync("select count(*) from audit_log where event like 'reaction%'"));
    }

    [DbFact]
    public async Task Reaction_route_returns_reactions_and_agents_spend_post_tokens()
    {
        var app = A1.Build(t, new Policy(), limited: true);
        var m = await Post("analyst", "react over REST");
        var (status, body) = A1.Read(await app.Api.React(A1.Request("analyst2", "POST", new { emoji = "👍" }), m.Id.ToString()));
        Assert.Equal(200, status);
        Assert.Equal("👍", body[0].GetProperty("emoji").GetString());
        Assert.Equal(1, body[0].GetProperty("count").GetInt32());
        Assert.Equal("analyst2", body[0].GetProperty("handles")[0].GetString());
        (status, body) = A1.Read(await app.Api.React(A1.Request("analyst2", "POST", new { emoji = "👍", op = "remove" }), m.Id.ToString()));
        Assert.Equal((200, 0), (status, body.GetArrayLength()));
        (status, _) = A1.Read(await app.Api.React(A1.Request("analyst2", "POST", new { emoji = "👍", op = "toggle" }), m.Id.ToString()));
        Assert.Equal(400, status);

        var agent = await t.As("agent");
        await app.Board.ReactAsync(agent, m.Id, "👀", false, Ct);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from rate_buckets where principal_id = @p and bucket = 'post'", ("p", agent.Id)));
    }

    // ── typing ────────────────────────────────────────────────────────────────────────────────

    [DbFact]
    public async Task Typing_in_a_thread_shows_to_others_in_that_thread_only()
    {
        var root = await Post("agent", "thread for typing", incident: TestBoard.IncidentGraphId);
        var reply = await Post("analyst2", "a reply", root.Id);
        await t.Board.TypingAsync(await t.As("analyst"), new TypingInput(Thread: reply.Id), Ct); // a reply id resolves to its root

        var who = await t.Board.WhoIsTypingAsync(await t.As("analyst2"), new TypingQuery(Thread: root.Id), Ct);
        Assert.Equal(("analyst", "Analyst", "human"), (who.Single().Handle, who.Single().DisplayName, who.Single().Kind));
        Assert.Empty(await t.Board.WhoIsTypingAsync(await t.As("analyst"), new TypingQuery(Thread: root.Id), Ct)); // never yourself
        // A thread isn't the channel's top-level composer, but it is on the incident.
        Assert.DoesNotContain(await t.Board.WhoIsTypingAsync(await t.As("analyst2"), new TypingQuery(Channel: "triage"), Ct), a => a.Handle == "analyst");
        Assert.Contains(await t.Board.WhoIsTypingAsync(await t.As("analyst2"), new TypingQuery(Incident: TestBoard.IncidentGraphId), Ct), a => a.Handle == "analyst");

        await TypingExpires(root.Id);
    }

    private async Task TypingExpires(Guid root)
    {
        await using (var c = t.Db.Command("update typing set until = now() - interval '1 second' where root_id = @r").With("r", root))
            await c.ExecuteNonQueryAsync(Ct);
        Assert.Empty(await t.Board.WhoIsTypingAsync(await t.As("analyst2"), new TypingQuery(Thread: root), Ct));
    }

    [DbFact]
    public async Task Typing_in_a_channel_is_top_level_and_incident_typing_finds_its_channel()
    {
        await t.Board.TypingAsync(await t.As("reader"), new TypingInput(Channel: "general"), Ct);
        Assert.Contains(await t.Board.WhoIsTypingAsync(await t.As("analyst"), new TypingQuery(Channel: "general"), Ct), a => a.Handle == "reader");
        Assert.DoesNotContain(await t.Board.WhoIsTypingAsync(await t.As("analyst"), new TypingQuery(Channel: "triage"), Ct), a => a.Handle == "reader");

        await t.Board.TypingAsync(await t.As("analyst2"), new TypingInput(Incident: TestBoard.IncidentGraphId), Ct);
        Assert.Contains(await t.Board.WhoIsTypingAsync(await t.As("analyst"), new TypingQuery(Incident: t.IncidentId.ToString()), Ct), a => a.Handle == "analyst2");
        Assert.Contains(await t.Board.WhoIsTypingAsync(await t.As("analyst"), new TypingQuery(Channel: "incidents"), Ct), a => a.Handle == "analyst2");
        await Assert.ThrowsAsync<BoardException>(() => t.Board.TypingAsync(t.As("analyst").Result, new TypingInput(), Ct));
        await Assert.ThrowsAsync<BoardException>(() => t.Board.WhoIsTypingAsync(t.As("analyst").Result, new TypingQuery(), Ct));
    }

    [DbFact]
    public async Task Typing_routes_return_204_and_the_list()
    {
        var app = A1.Build(t, new Policy());
        var root = await Post("analyst", "typing over REST");
        var (status, _) = A1.Read(await app.Api.Typing(A1.Request("analyst2", "POST", new { thread = root.Id })));
        Assert.Equal(204, status);
        var (s2, body) = A1.Read(await app.Api.WhoIsTyping(A1.Request("analyst", query: $"?thread={root.Id}")));
        Assert.Equal(200, s2);
        Assert.Equal("analyst2", body[0].GetProperty("handle").GetString());
        Assert.Equal("Second Analyst", body[0].GetProperty("display_name").GetString());
        Assert.Equal("human", body[0].GetProperty("kind").GetString());
        Assert.Equal(1, body.GetArrayLength());
    }

    [DbFact]
    public async Task Agent_set_typing_uses_the_message_thread_and_lasts_until_turned_off()
    {
        var root = await Post("analyst", "@agent can you look?", incident: TestBoard.IncidentGraphId);
        var reply = await Post("analyst", "and this", root.Id);
        var agent = await t.As("agent");
        await t.Board.SetTypingAsync(agent, reply.Id, true, Ct);
        await t.Board.SetTypingAsync(agent, reply.Id, true, Ct); // renew: still one row
        Assert.Equal(1, await t.ScalarAsync("select count(*) from typing where principal_id = @p and root_id = @r", ("p", agent.Id), ("r", root.Id)));
        Assert.InRange(await t.ScalarAsync("select extract(epoch from until - now())::int from typing where principal_id = @p", ("p", agent.Id)), 25, 30);
        var who = await t.Board.WhoIsTypingAsync(await t.As("analyst"), new TypingQuery(Thread: root.Id), Ct);
        Assert.Equal(("agent", "agent"), (who.Single().Handle, who.Single().Kind));

        await t.Board.SetTypingAsync(agent, root.Id, false, Ct);
        Assert.Empty(await t.Board.WhoIsTypingAsync(await t.As("analyst"), new TypingQuery(Thread: root.Id), Ct));
    }
}
