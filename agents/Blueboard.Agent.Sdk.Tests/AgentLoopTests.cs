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

    public Message Add(string type, string body, string author = "analyst", string channel = "intel", string[]? mentions = null, Guid? parent = null, string kind = "human")
    {
        var m = new Message(Guid.NewGuid(), (Feed.Count + 1).ToString(), channel, new Author(author, author, kind), parent, null, null,
            type, body, null, mentions ?? [], "open", null, null, DateTimeOffset.UtcNow, 0);
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
            "read_feed" => ReadFeed(args.TryGetValue("after_seq", out var a) && a is not null ? long.Parse(a.ToString()!) : (long?)null, args.TryGetValue("limit", out var l) ? Convert.ToInt32(l!.ToString()) : 50),
            "claim_message" when ClaimedBy.TryGetValue(Guid.Parse(S("message_id")), out var who) && who != Me => "error: already claimed by @" + who + " (status 409)",
            "claim_message" => Claim(Guid.Parse(S("message_id"))),
            "renew_claim" => ClaimedBy.GetValueOrDefault(Guid.Parse(S("message_id"))) == Me ? Find(S("message_id")) : "error: you do not hold a claim (status 409)",
            "complete_claim" => Complete(Guid.Parse(S("message_id"))),
            "post_message" => Add(args.TryGetValue("type", out var t) ? t?.ToString() ?? "chat" : "chat", S("body"), Me, S("channel")),
            _ => $"error: unknown tool {tool} (status 400)",
        };
        return Task.FromResult(result as string ?? JsonSerializer.Serialize(result, BoardJson.Options));
    }

    private FeedResult ReadFeed(long? after, int limit)
    {
        var rows = after is null ? Feed.TakeLast(limit).ToList() : Feed.Where(m => long.Parse(m.Seq) > after).Take(limit).ToList();
        return new FeedResult(rows, rows.Count > 0 ? rows[^1].Seq : after?.ToString());
    }

    private Message Find(string id) => Feed.First(m => m.Id.ToString() == id);
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

    private async Task RunOnce(FakeBoard fake, AgentHandler? onQuestion, AgentHandler? onMention)
    {
        await using var board = BoardConnection.Over(fake);
        var state = await AgentState.LoadAsync(StateFile, Ct);
        await BoardAgent.PollOnceAsync(board, Options, state, fake.Me, null, onQuestion, onMention, Ct);
    }
}
