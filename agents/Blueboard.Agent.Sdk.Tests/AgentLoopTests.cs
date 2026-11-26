using System.Text.Json;
using Blueboard.Agent;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Agent.Sdk.Tests;

/// <summary>A board in memory: answers read_feed, claim/renew/complete and post_message like the real one.</summary>
internal sealed class FakeBoard : IBoardTransport
{
    public readonly List<Message> Feed = [];
    public readonly List<(string Tool, Dictionary<string, object?> Args)> Calls = [];
    public readonly Dictionary<Guid, string> ClaimedBy = [];
    public string Me = "agent";
    /// <summary>Make react and set_typing fail, to check they never stop the work.</summary>
    public bool CosmeticFails;

    public Message Add(string type, string body, string author = "analyst", string channel = "intel", string[]? mentions = null, Guid? parent = null, string kind = "human",
        Guid? incident = null, DateTimeOffset? at = null)
    {
        var m = new Message(Guid.NewGuid(), (Feed.Count + 1).ToString(), channel, new Author(author, author, kind), parent, incident, null,
            type, body, null, mentions ?? [], "open", null, null, at ?? DateTimeOffset.UtcNow, 0);
        Feed.Add(m);
        return m;
    }

    public Task<string> CallAsync(string tool, IReadOnlyDictionary<string, object?> args, CancellationToken ct)
    {
        Calls.Add((tool, args.ToDictionary()));
        string S(string k) => args[k]!.ToString()!;
        object result = tool switch
        {
            "whoami" => new Identity(Guid.NewGuid(), Me, Me, "agent", ["poster"]),
            "read_feed" => ReadFeed(args.TryGetValue("after_seq", out var a) && a is not null ? long.Parse(a.ToString()!) : (long?)null, args.TryGetValue("limit", out var l) ? Convert.ToInt32(l!.ToString()) : 50,
                args.TryGetValue("open_requests", out var o) && string.Equals(o?.ToString(), "true", StringComparison.OrdinalIgnoreCase)),
            "claim_message" when ClaimedBy.TryGetValue(Guid.Parse(S("message_id")), out var who) && who != Me => "error: already claimed by @" + who + " (status 409)",
            "claim_message" => Claim(Guid.Parse(S("message_id"))),
            "renew_claim" => ClaimedBy.GetValueOrDefault(Guid.Parse(S("message_id"))) == Me ? Find(S("message_id")) : "error: you do not hold a claim (status 409)",
            "complete_claim" => Complete(Guid.Parse(S("message_id"))),
            "get_thread" => Thread(Guid.Parse(S("message_id"))),
            "react" or "set_typing" when CosmeticFails => "error: internal error (status 500)",
            "react" => new[] { new Reaction(S("emoji"), 1, [Me]) },
            "set_typing" => new { active = string.Equals(S("active"), "true", StringComparison.OrdinalIgnoreCase) },
            "post_message" => Add(args.TryGetValue("type", out var t) ? t?.ToString() ?? "chat" : "chat", S("body"), Me, S("channel"), kind: "agent",
                parent: args.TryGetValue("parent_id", out var pid) && pid is not null ? Guid.Parse(pid.ToString()!) : null,
                incident: args.TryGetValue("incident", out var inc) && inc is not null ? Guid.Parse(inc.ToString()!) : null),
            _ => $"error: unknown tool {tool} (status 400)",
        };
        return Task.FromResult(result as string ?? JsonSerializer.Serialize(result, BoardJson.Options));
    }

    private FeedResult ReadFeed(long? after, int limit, bool openRequests)
    {
        var feed = openRequests ? Feed.Where(m => BoardAgent.ClaimableTypes.Contains(m.Type) && !ClaimedBy.ContainsKey(m.Id)).ToList() : Feed;
        var rows = after is null ? feed.TakeLast(limit).ToList() : feed.Where(m => long.Parse(m.Seq) > after).Take(limit).ToList();
        return new FeedResult(rows, rows.Count > 0 ? rows[^1].Seq : after?.ToString());
    }

    private Message Find(string id) => Feed.First(m => m.Id.ToString() == id);
    private ThreadResult Thread(Guid id)
    {
        var root = Find(id.ToString());
        if (ClaimedBy.TryGetValue(id, out var who)) root = root with { ClaimState = "claimed", ClaimedBy = who };
        return new ThreadResult(root, Feed.Where(m => m.ParentId == id).ToList());
    }
    private Message Claim(Guid id) { ClaimedBy[id] = Me; return Find(id.ToString()); }
    private Message Complete(Guid id) { ClaimedBy.Remove(id); return Find(id.ToString()); }

    public int Count(string tool) => Calls.Count(c => c.Tool == tool);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public class AgentLoopTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bb-sdk-" + Guid.NewGuid().ToString("N"));
    private string StateFile => Path.Combine(_dir, "state.json");
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private LoopOptions Options => new() { StateFile = StateFile, PollInterval = TimeSpan.FromMilliseconds(10) };

    [Fact]
    public async Task Never_double_processes_after_restart()
    {
        var fake = new FakeBoard();
        fake.Add("chat", "before the agent started");
        var handled = new List<Guid>();
        AgentHandler onMention = (w, _) => { handled.Add(w.Message.Id); return Task.CompletedTask; };

        // First run starts at the end of the feed: history is not replayed.
        await using (var board = BoardConnection.Over(fake))
        {
            var state = await AgentState.LoadAsync(StateFile, Ct);
            state.Cursor = (await board.ReadFeedAsync(new FeedQuery(Limit: 1), Ct)).Cursor;
            await state.SaveAsync(StateFile, Ct);
        }
        var m1 = fake.Add("chat", "@agent first", mentions: ["agent"]);
        var m2 = fake.Add("chat", "@agent second", mentions: ["agent"]);
        await RunOnce(fake, null, onMention);
        Assert.Equal([m1.Id, m2.Id], handled);

        // "Restart": a fresh process with only the state file. Nothing is handled twice; new work is picked up.
        var m3 = fake.Add("chat", "@agent third", mentions: ["agent"]);
        await RunOnce(fake, null, onMention);
        await RunOnce(fake, null, onMention);
        Assert.Equal([m1.Id, m2.Id, m3.Id], handled);
    }

    [Fact]
    public async Task Crash_after_handling_but_before_cursor_save_does_not_repeat()
    {
        var fake = new FakeBoard();
        var m = fake.Add("chat", "@agent once only", mentions: ["agent"]);
        // The state as a crash would leave it: the message is done but the cursor never advanced past it.
        var state = new AgentState { Cursor = "0" };
        state.MarkDone(m.Id);
        await state.SaveAsync(StateFile, Ct);
        var handled = 0;
        await RunOnce(fake, null, (_, _) => { handled++; return Task.CompletedTask; });
        Assert.Equal(0, handled);
        Assert.Equal(m.Seq, (await AgentState.LoadAsync(StateFile, Ct)).Cursor);
    }

    [Fact]
    public async Task Claims_before_work_completes_on_success_and_releases_on_error()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var ok = fake.Add("question", "who owns 203.0.113.9?");
        var bad = fake.Add("question", "this one throws");
        await RunOnce(fake, (w, _) => w.Message.Id == bad.Id ? throw new InvalidOperationException("boom") : w.ReplyAsync("it's ours", ct: Ct), null);

        var order = fake.Calls.Select(c => c.Tool).ToList();
        Assert.True(order.IndexOf("claim_message") < order.IndexOf("post_message"));
        var completes = fake.Calls.Where(c => c.Tool == "complete_claim").Select(c => (c.Args["message_id"]!.ToString(), c.Args["outcome"]!.ToString())).ToList();
        Assert.Contains((ok.Id.ToString(), "done"), completes);
        Assert.Contains((bad.Id.ToString(), "release"), completes);
    }

    [Fact]
    public async Task Someone_elses_claim_is_skipped()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var q = fake.Add("question", "already taken");
        fake.ClaimedBy[q.Id] = "agent2";
        var handled = 0;
        await RunOnce(fake, (_, _) => { handled++; return Task.CompletedTask; }, null);
        Assert.Equal(0, handled);
        Assert.Equal(0, fake.Count("complete_claim"));
    }

    [Fact]
    public async Task Released_question_is_picked_up_by_the_rescan_once()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var q = fake.Add("question", "agent2 had this, then let it go");
        fake.ClaimedBy[q.Id] = "agent2";
        var handled = 0;
        AgentHandler onQuestion = (_, _) => { handled++; return Task.CompletedTask; };
        await RunOnce(fake, onQuestion, null);
        Assert.Equal(0, handled);

        // agent2 releases it (or its lease expires): the cursor has moved on, only the open-requests rescan finds it.
        fake.ClaimedBy.Remove(q.Id);
        await RunOnce(fake, onQuestion, null);
        Assert.Equal(0, handled);
        await Rescan(fake, onQuestion);
        Assert.Equal(1, handled);
        Assert.Contains(fake.Calls, c => c.Tool == "complete_claim" && c.Args["message_id"]!.ToString() == q.Id.ToString() && c.Args["outcome"]!.ToString() == "done");

        // Handled once: a later rescan (the fake keeps it open) doesn't run it again.
        await Rescan(fake, onQuestion);
        Assert.Equal(1, handled);
    }

    [Fact]
    public async Task Rescan_skips_open_requests_the_agent_already_handled_or_does_not_take()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        fake.Add("question", "answered in the normal pass");
        fake.Add("finding", "nobody mentioned the agent");
        var handled = 0;
        AgentHandler onQuestion = (_, _) => { handled++; return Task.CompletedTask; };
        await RunOnce(fake, onQuestion, null);
        fake.ClaimedBy.Clear(); // the fake doesn't record done: keep both "open" so the rescan sees them
        await Rescan(fake, onQuestion);
        Assert.Equal(1, handled);
    }

    [Fact]
    public async Task Run_loop_rescans_open_requests()
    {
        var fake = new FakeBoard();
        var q = fake.Add("question", "held by someone else when the agent started");
        fake.ClaimedBy[q.Id] = "agent2";
        await new AgentState { Cursor = q.Seq }.SaveAsync(StateFile, Ct);
        fake.ClaimedBy.Remove(q.Id);
        var handled = new TaskCompletionSource();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        await using var board = BoardConnection.Over(fake);
        var loop = BoardAgent.RunLoopAsync(board, Options with { RescanInterval = TimeSpan.FromMilliseconds(10) },
            onQuestion: (_, _) => { handled.TrySetResult(); return Task.CompletedTask; }, ct: cts.Token);
        Assert.Same(handled.Task, await Task.WhenAny(handled.Task, Task.Delay(5000, Ct)));
        await cts.CancelAsync();
        await loop;
    }

    [Fact]
    public async Task Lease_is_renewed_while_work_runs()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        fake.Add("question", "slow one");
        var o = Options with { LeaseSeconds = 30 };
        await using var board = BoardConnection.Over(fake);
        var state = await AgentState.LoadAsync(StateFile, Ct);
        // Renewal runs every max(15 s, lease/2): use a handler that outlasts one period.
        var task = BoardAgent.PollOnceAsync(board, o, state, "agent", null, async (_, ct) => await Task.Delay(TimeSpan.FromSeconds(16), ct), null, Ct);
        await task;
        Assert.True(fake.Count("renew_claim") >= 1);
    }

    [Fact]
    public async Task Own_messages_and_unrelated_chat_are_ignored()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        fake.Add("chat", "@agent talking to myself", author: "agent", mentions: ["agent"]);
        fake.Add("chat", "general chatter");
        // The board's own action record names the requester: not a request for help.
        fake.Add("action_request", "@agent requests **Isolate device**", author: "board", channel: "containment", mentions: ["agent"], kind: "system");
        var handled = 0;
        await RunOnce(fake, (_, _) => { handled++; return Task.CompletedTask; }, (_, _) => { handled++; return Task.CompletedTask; });
        Assert.Equal(0, handled);
    }

    [Fact]
    public async Task Scheduled_followup_from_board_wakes_mention_handler()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var m = new Message(Guid.NewGuid(), "1", "intel", new Author("board", "Blueboard", "system"), null, null, null,
            "status", "Follow-up for @agent (scheduled by @agent):\n\n> check whether isolate completed",
            JsonDocument.Parse("""{"state":"followup"}""").RootElement, ["agent"], "open", null, null, DateTimeOffset.UtcNow, 0);
        fake.Feed.Add(m);
        var handled = new List<Guid>();
        await RunOnce(fake, null, (w, _) => { handled.Add(w.Message.Id); return Task.CompletedTask; });
        Assert.Equal([m.Id], handled);
    }

    [Fact]
    public void Tool_errors_parse_status()
    {
        var e = BoardConnection.Parse("renew_claim", "error: claimed by @x, not you (status 409)");
        Assert.True(e.IsConflict);
        Assert.Equal("renew_claim: claimed by @x, not you", e.Message);
        Assert.Equal(403, BoardConnection.Parse("t", "error: missing role hunter (status 403)").Status);
    }

    [Fact]
    public void Webhook_receiver_checks_signatures()
    {
        var rx = new WebhookReceiver("whsec_test");
        var body = JsonSerializer.Serialize(new WebhookEvent("mention", Guid.NewGuid(), "7", Guid.NewGuid(), Guid.NewGuid()), BoardJson.Options);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.Equal(401, rx.Accept(body, ts.ToString(), "sha256=00"));
        Assert.False(rx.Events.TryRead(out _));
        Assert.Equal(204, rx.Accept(body, ts.ToString(), WebhookSignature.Sign("whsec_test", ts, body)));
        Assert.True(rx.Events.TryRead(out var evt));
        Assert.Equal("mention", evt.Event);
    }

    [Fact]
    public async Task Webhook_mode_wakes_the_loop_early()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var rx = new WebhookReceiver("whsec_test");
        var handled = new TaskCompletionSource();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        await using var board = BoardConnection.Over(fake);
        // Long safety-net poll: only the webhook can wake it within the test.
        var loop = BoardAgent.RunLoopAsync(board, Options with { PollInterval = TimeSpan.FromMinutes(5), Wakeups = rx.Events },
            onMention: (_, _) => { handled.TrySetResult(); return Task.CompletedTask; }, ct: cts.Token);
        await Task.Delay(200, Ct); // first pass finds nothing and goes to sleep
        fake.Add("chat", "@agent wake up", mentions: ["agent"]);
        var body = JsonSerializer.Serialize(new WebhookEvent("mention", Guid.NewGuid(), "1", Guid.NewGuid(), Guid.NewGuid()), BoardJson.Options);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.Equal(204, rx.Accept(body, ts.ToString(), WebhookSignature.Sign("whsec_test", ts, body)));
        Assert.Same(handled.Task, await Task.WhenAny(handled.Task, Task.Delay(5000, Ct)));
        await cts.CancelAsync();
        await loop;
    }

    [Fact]
    public async Task Work_item_handoff_posts_question_and_releases_claim()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var q = fake.Add("question", "Needs Sentinel Log Analytics check");
        await RunOnce(fake, async (work, ct) =>
        {
            await work.PostFindingAsync("Initial check done", 0.7, ct: ct);
            await work.HandoffAsync("@sentinel-hunter", "please query AuditLogs for this user", ct);
        }, null);

        Assert.Contains(fake.Calls, c => c.Tool == "post_message" && c.Args["type"]!.ToString() == "finding");
        Assert.Contains(fake.Calls, c => c.Tool == "post_message" && c.Args["type"]!.ToString() == "question" && c.Args["body"]!.ToString()!.Contains("@sentinel-hunter"));
        Assert.Contains(fake.Calls, c => c.Tool == "complete_claim" && c.Args["message_id"]!.ToString() == q.Id.ToString() && c.Args["outcome"]!.ToString() == "release");
    }

    // ── conversations: people replying to the agent without an @mention ──────────────────────────
    private (List<WorkItem> Handled, AgentHandler Handler) Recorder()
    {
        var handled = new List<WorkItem>();
        return (handled, (w, _) => { handled.Add(w); return Task.CompletedTask; });
    }

    [Fact]
    public async Task Human_reply_in_a_thread_the_agent_posted_in_reaches_the_mention_handler()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var root = fake.Add("finding", "the agent's finding", author: "agent", kind: "agent");
        var other = fake.Add("chat", "a person's thread");
        fake.Add("chat", "agent chimes in", author: "agent", kind: "agent", parent: other.Id);
        var (handled, onMention) = Recorder();
        await RunOnce(fake, null, onMention);

        // Separate pass (and state reload): the threads are remembered in the state file.
        var reply = fake.Add("chat", "that host is a test box", parent: root.Id);
        var reply2 = fake.Add("chat", "agreed, nothing to see", author: "analyst2", parent: other.Id);
        await RunOnce(fake, null, onMention);
        Assert.Equal([reply.Id, reply2.Id], handled.Select(w => w.Message.Id));
        Assert.All(handled, w => Assert.True(w.Conversation));
        Assert.Equal(0, fake.Count("claim_message")); // chats aren't claimed
    }

    [Fact]
    public async Task Agent_and_system_replies_in_the_agents_thread_are_ignored()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var root = fake.Add("finding", "the agent's finding", author: "agent", kind: "agent");
        fake.Add("chat", "another agent replies", author: "agent2", kind: "agent", parent: root.Id);
        fake.Add("status", "board status in the thread", author: "board", kind: "system", parent: root.Id);
        fake.Add("chat", "@agent2 can you check the proxy?", parent: root.Id, mentions: ["agent2"]); // talking to someone else
        var (handled, onMention) = Recorder();
        await RunOnce(fake, onMention, onMention);
        Assert.Empty(handled);
    }

    [Fact]
    public async Task Human_reply_in_an_unrelated_thread_is_ignored()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var root = fake.Add("chat", "people talking");
        fake.Add("chat", "still people talking", author: "analyst2", parent: root.Id);
        var (handled, onMention) = Recorder();
        await RunOnce(fake, null, onMention);
        Assert.Empty(handled);
    }

    [Fact]
    public async Task Human_question_in_the_agents_thread_is_claimed_and_answered()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var root = fake.Add("finding", "the agent's finding", author: "agent", kind: "agent", channel: "incidents");
        var q = fake.Add("question", "was this the only device?", parent: root.Id, channel: "incidents");
        var (handled, onMention) = Recorder();
        await RunOnce(fake, null, onMention);
        Assert.Equal([q.Id], handled.Select(w => w.Message.Id));
        Assert.True(handled[0].Claimed);
        Assert.Contains(fake.Calls, c => c.Tool == "complete_claim" && c.Args["message_id"]!.ToString() == q.Id.ToString());
    }

    [Fact]
    public async Task Top_level_human_chat_on_an_incident_the_agent_posted_on_reaches_it()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var incident = Guid.NewGuid();
        var root = fake.Add("incident", "Incident 90210", author: "board", kind: "system", channel: "incidents", incident: incident);
        fake.Add("question", "Is the PowerShell download expected?", author: "agent", kind: "agent", channel: "incidents", parent: root.Id, incident: incident);
        var (handled, onMention) = Recorder();
        await RunOnce(fake, null, onMention);

        var answer = fake.Add("chat", "this was just a test", channel: "incidents", incident: incident);
        await RunOnce(fake, null, onMention);
        Assert.Equal([answer.Id], handled.Select(w => w.Message.Id));
        Assert.True(handled[0].Conversation);
    }

    [Fact]
    public async Task Top_level_chat_on_another_or_stale_incident_is_ignored()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var mine = Guid.NewGuid();
        fake.Add("finding", "agent posted on this incident two days ago", author: "agent", kind: "agent", channel: "incidents", incident: mine,
            at: DateTimeOffset.UtcNow.AddDays(-2));
        var (handled, onMention) = Recorder();
        await RunOnce(fake, null, onMention);

        fake.Add("chat", "a different incident", channel: "incidents", incident: Guid.NewGuid());
        fake.Add("chat", "the agent hasn't posted here for two days", channel: "incidents", incident: mine);
        fake.Add("chat", "another agent on the agent's incident", author: "agent2", kind: "agent", channel: "incidents", incident: mine);
        await RunOnce(fake, null, onMention);
        Assert.Empty(handled);
    }

    [Fact]
    public async Task Agents_own_replies_are_remembered_so_the_answer_to_them_is_heard()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var q = fake.Add("chat", "@agent what is 203.0.113.9?", mentions: ["agent"]);
        var (handled, onMention) = Recorder();
        await RunOnce(fake, null, async (w, ct) => { await onMention(w, ct); await w.ReplyAsync("@analyst it's our proxy. Was this expected?", ct: ct); });
        var followUp = fake.Add("chat", "yes, expected", parent: q.Id);
        await RunOnce(fake, null, onMention);
        Assert.Equal([q.Id, followUp.Id], handled.Select(w => w.Message.Id));
    }

    [Fact]
    public void Conversation_memory_is_capped()
    {
        var state = new AgentState();
        var first = Guid.NewGuid();
        state.MarkPosted(first, Guid.NewGuid(), DateTimeOffset.UtcNow);
        for (var i = 0; i < AgentState.MaxConversations + 10; i++) state.MarkPosted(Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow);
        Assert.Equal(AgentState.MaxConversations, state.Threads.Count);
        Assert.Equal(AgentState.MaxConversations, state.Incidents.Count);
        Assert.False(state.InThread(first));
    }

    [Fact]
    public async Task Close_own_question_leaves_a_question_someone_else_holds()
    {
        var fake = new FakeBoard();
        var mine = fake.Add("question", "is this expected?", author: "agent", kind: "agent");
        var held = fake.Add("question", "who owns this host?", author: "agent", kind: "agent");
        fake.ClaimedBy[held.Id] = "analyst";
        await using var board = BoardConnection.Over(fake);
        var work = new WorkItem(board, mine, "agent", claimed: false);
        Assert.Equal("done", await work.CloseOwnQuestionAsync(mine.Id, Ct));
        Assert.StartsWith("left open", await work.CloseOwnQuestionAsync(held.Id, Ct));
        Assert.DoesNotContain(fake.Calls, c => c.Tool == "complete_claim" && c.Args["message_id"]!.ToString() == held.Id.ToString());
    }

    [Fact]
    public async Task Reacts_with_eyes_after_the_claim_and_types_while_the_handler_runs()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var q = fake.Add("question", "@agent who owns 203.0.113.9?", mentions: ["agent"]);
        List<string> during = [];
        await RunOnce(fake, null, (w, _) => { during.AddRange(fake.Calls.Select(c => c.Tool)); return Task.CompletedTask; });

        var order = fake.Calls.Select(c => c.Tool).ToList();
        Assert.True(order.IndexOf("claim_message") < order.IndexOf("react"));
        var react = fake.Calls.Single(c => c.Tool == "react");
        Assert.Equal(q.Id.ToString(), react.Args["message_id"]!.ToString());
        Assert.Equal("👀", react.Args["emoji"]!.ToString());
        // Typing was on before the handler finished, and turned off before the claim was settled.
        var typing = fake.Calls.Where(c => c.Tool == "set_typing").ToList();
        Assert.Equal("True", typing[0].Args["active"]!.ToString());
        Assert.Equal("False", typing[^1].Args["active"]!.ToString());
        Assert.True(order.LastIndexOf("set_typing") < order.IndexOf("complete_claim"));
    }

    [Fact]
    public async Task Chat_mention_gets_eyes_without_a_claim()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        fake.Add("chat", "@agent resolve this as a false positive", mentions: ["agent"]);
        await RunOnce(fake, null, (_, _) => Task.CompletedTask);
        Assert.Equal(0, fake.Count("claim_message"));
        Assert.Equal(1, fake.Count("react"));
    }

    [Fact]
    public async Task Typing_is_renewed_while_a_long_handler_runs()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        fake.Add("chat", "@agent hunt for this", mentions: ["agent"]);
        await using var board = BoardConnection.Over(fake);
        var state = await AgentState.LoadAsync(StateFile, Ct);
        await BoardAgent.PollOnceAsync(board, Options with { TypingRenewInterval = TimeSpan.FromMilliseconds(20) }, state, fake.Me, null, null,
            async (_, ct) => await Task.Delay(200, ct), Ct);
        var active = fake.Calls.Count(c => c.Tool == "set_typing" && c.Args["active"]!.ToString() == "True");
        Assert.True(active >= 3, $"typing renewed {active} times");
        Assert.Equal("False", fake.Calls.Last(c => c.Tool == "set_typing").Args["active"]!.ToString());
    }

    [Fact]
    public async Task Incidents_get_no_eyes_or_typing()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        fake.Add("incident", "Incident 90210", author: "board", kind: "system", channel: "incidents", incident: Guid.NewGuid());
        var handled = 0;
        await using var board = BoardConnection.Over(fake);
        var state = await AgentState.LoadAsync(StateFile, Ct);
        await BoardAgent.PollOnceAsync(board, Options, state, fake.Me, (_, _) => { handled++; return Task.CompletedTask; }, null, null, Ct);
        Assert.Equal(1, handled);
        Assert.Equal(0, fake.Count("react"));
        Assert.Equal(0, fake.Count("set_typing"));
    }

    [Fact]
    public async Task Ack_and_typing_can_be_turned_off()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        fake.Add("question", "who owns 203.0.113.9?");
        await using var board = BoardConnection.Over(fake);
        var state = await AgentState.LoadAsync(StateFile, Ct);
        await BoardAgent.PollOnceAsync(board, Options with { AckReaction = null, ShowTyping = false }, state, fake.Me, null, (_, _) => Task.CompletedTask, null, Ct);
        Assert.Equal(1, fake.Count("claim_message"));
        Assert.Equal(0, fake.Count("react"));
        Assert.Equal(0, fake.Count("set_typing"));
    }

    [Fact]
    public async Task Failed_reaction_or_typing_never_fails_the_work()
    {
        var fake = new FakeBoard { CosmeticFails = true };
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var q = fake.Add("question", "who owns 203.0.113.9?");
        var handled = 0;
        await RunOnce(fake, (_, _) => { handled++; return Task.CompletedTask; }, null);
        Assert.Equal(1, handled);
        Assert.Contains(fake.Calls, c => c.Tool == "complete_claim" && c.Args["message_id"]!.ToString() == q.Id.ToString() && c.Args["outcome"]!.ToString() == "done");
    }

    [Fact]
    public async Task Work_item_react_reacts_to_its_message()
    {
        var fake = new FakeBoard();
        await new AgentState { Cursor = "0" }.SaveAsync(StateFile, Ct);
        var m = fake.Add("chat", "@agent thanks!", mentions: ["agent"]);
        await using var board = BoardConnection.Over(fake);
        var state = await AgentState.LoadAsync(StateFile, Ct);
        Reaction[]? got = null;
        await BoardAgent.PollOnceAsync(board, Options with { AckReaction = null }, state, fake.Me, null, null, async (w, ct) => got = await w.ReactAsync("👍", ct), Ct);
        Assert.Equal("👍", Assert.Single(got!).Emoji);
        Assert.Equal(m.Id.ToString(), fake.Calls.Single(c => c.Tool == "react").Args["message_id"]!.ToString());
    }

    private async Task RunOnce(FakeBoard fake, AgentHandler? onQuestion, AgentHandler? onMention)
    {
        await using var board = BoardConnection.Over(fake);
        var state = await AgentState.LoadAsync(StateFile, Ct);
        await BoardAgent.PollOnceAsync(board, Options, state, fake.Me, null, onQuestion, onMention, Ct);
    }

    private async Task Rescan(FakeBoard fake, AgentHandler onQuestion)
    {
        await using var board = BoardConnection.Over(fake);
        var state = await AgentState.LoadAsync(StateFile, Ct);
        await BoardAgent.RescanOpenAsync(board, Options, state, fake.Me, onQuestion, null, Ct);
    }
}
