using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Webhooks;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Issues #12, #13 and #23 against a real Postgres: renew_claim, last_seen throttle, webhooks, follow-ups.</summary>
public sealed class AgentWakeupTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private const string Host = "hooks.contoso.com";
    private static readonly string Key = Convert.ToBase64String(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());

    /// <summary>Records every webhook POST in-process; resolution is faked to a public address.</summary>
    private sealed class Receiver : HttpMessageHandler
    {
        public readonly ConcurrentQueue<(WebhookEvent Event, string Body, string? Sig, string? Ts)> Got = new();
        public HttpStatusCode Status = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = await request.Content!.ReadAsStringAsync(ct);
            Got.Enqueue((JsonSerializer.Deserialize<WebhookEvent>(body, BoardJson.Options)!, body,
                request.Headers.TryGetValues(WebhookEvents.SignatureHeader, out var s) ? s.First() : null,
                request.Headers.TryGetValues(WebhookEvents.TimestampHeader, out var ts) ? ts.First() : null));
            return new HttpResponseMessage(Status);
        }
    }

    private (WebhookService Hooks, Receiver Rx) Hooks(Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null)
    {
        var settings = t.Settings with { WebhookAllowedHosts = [Host], WebhookSigningKey = Key };
        var rx = new Receiver();
        return (new WebhookService(t.Db, t.Audit, t.Board, t.System, settings, new HttpClient(rx),
            resolve ?? ((_, _) => Task.FromResult(new[] { IPAddress.Parse("20.53.1.10") }))), rx);
    }

    [DbFact]
    public async Task Renew_extends_only_your_own_lease()
    {
        var q = await t.Board.PostAsync(await t.As("analyst"), new PostInput("intel", "renewal check", "question"), ct: Ct);
        var agent = await t.As("agent");
        var claimed = await t.Board.ClaimAsync(agent, q.Id, 30, Ct);
        var renewed = await t.Board.RenewClaimAsync(agent, q.Id, 900, Ct);
        Assert.True(renewed.ClaimExpiresAt > claimed.ClaimExpiresAt!.Value.AddMinutes(10));
        var other = await t.As("agent2");
        var ex = await Assert.ThrowsAsync<BoardException>(() => t.Board.RenewClaimAsync(other, q.Id, 900, Ct));
        Assert.Equal(409, ex.Status);
        // An expired lease can't be renewed (someone else may have it by now): claim again instead.
        await using (var c = t.Db.Command("update messages set claim_expires_at = now() - interval '1 second' where id = @id").With("id", q.Id))
            await c.ExecuteNonQueryAsync(Ct);
        Assert.Equal(409, (await Assert.ThrowsAsync<BoardException>(() => t.Board.RenewClaimAsync(agent, q.Id, 900, Ct))).Status);
    }

    [DbFact]
    public async Task Last_seen_is_written_at_most_once_a_minute()
    {
        var auth = new Authenticator(t.Settings, new TokenValidator(t.Settings), t.Db, t.Audit);
        var headers = new Dictionary<string, string> { ["authorization"] = "Bearer dev:agent2" };
        await using (var c = t.Db.Command("update principals set last_seen_at = null where handle = 'agent2'")) await c.ExecuteNonQueryAsync(Ct);
        await auth.AuthenticateAsync(headers, Ct);
        var first = await LastSeen();
        // Concurrent, as under real load (this also caught a reader double-dispose on pooled connections).
        await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => auth.AuthenticateAsync(headers, Ct)));
        Assert.Equal(first, await LastSeen()); // 50 requests, no new write
        await using (var c = t.Db.Command("update principals set last_seen_at = now() - interval '61 seconds' where handle = 'agent2'")) await c.ExecuteNonQueryAsync(Ct);
        var stale = await LastSeen();
        await auth.AuthenticateAsync(headers, Ct);
        Assert.True(await LastSeen() > stale);

        async Task<DateTimeOffset> LastSeen()
        {
            await using var c = t.Db.Command("select last_seen_at from principals where handle = 'agent2'");
            await using var r = await c.ExecuteReaderAsync(Ct);
            await r.ReadAsync(Ct);
            return r.GetFieldValue<DateTimeOffset>(0);
        }
    }

    [DbFact]
    public async Task Subscribe_refuses_hosts_off_the_allowlist_and_private_addresses()
    {
        var (hooks, _) = Hooks();
        var agent = await t.As("agent");
        var off = await Assert.ThrowsAsync<BoardException>(() => hooks.SubscribeAsync(agent, new SubscribeInput("https://evil.example/x", ["mention"]), Ct));
        Assert.Equal(403, off.Status);
        var (rebound, _) = Hooks((_, _) => Task.FromResult(new[] { IPAddress.Parse("10.0.0.5") }));
        var priv = await Assert.ThrowsAsync<BoardException>(() => rebound.SubscribeAsync(agent, new SubscribeInput($"https://{Host}/x", ["mention"]), Ct));
        Assert.Contains("non-public", priv.Message);
        await Assert.ThrowsAsync<BoardException>(() => hooks.SubscribeAsync(agent, new SubscribeInput($"https://{Host}/x", ["everything"]), Ct));
    }

    [DbFact]
    public async Task Mention_and_thread_reply_are_delivered_signed_with_ids_only()
    {
        var (hooks, rx) = Hooks();
        await hooks.EnqueueAsync(Ct); // start the cursor at the end of the feed
        var agent = await t.As("agent2");
        var sub = await hooks.SubscribeAsync(agent, new SubscribeInput($"https://{Host}/wake", ["mention", "thread.reply"]), Ct);
        Assert.StartsWith("whsec_", sub.Secret);

        var analyst = await t.As("analyst");
        var root = await t.Board.PostAsync(agent, new PostInput("triage", "agent2 started this thread", "finding"), ct: Ct);
        var mention = await t.Board.PostAsync(analyst, new PostInput("triage", "@agent2 can you check the proxy logs?", "chat", null, root.Id), ct: Ct);
        await t.Board.PostAsync(analyst, new PostInput("general", "secret body text nobody should see in a webhook"), ct: Ct);

        var r = await hooks.RunOnceAsync(Ct);
        Assert.Equal(2, rx.Got.Count); // mention + thread.reply on the same message; the general post isn't for agent2
        foreach (var (evt, body, sig, ts) in rx.Got)
        {
            Assert.Equal(mention.Id, evt.MessageId);
            Assert.DoesNotContain("proxy", body);
            Assert.True(WebhookSignature.Verify(sub.Secret!, ts, body, sig));
        }
        Assert.Equal(["mention", "thread.reply"], rx.Got.Select(g => g.Event.Event).Order());

        // Delivered once: another tick sends nothing new.
        await hooks.RunOnceAsync(Ct);
        Assert.Equal(2, rx.Got.Count);
        await hooks.UnsubscribeAsync(agent, sub.Id, Ct);
    }

    [DbFact]
    public async Task Action_decided_and_claim_expired_reach_the_requester()
    {
        var (hooks, rx) = Hooks();
        await hooks.EnqueueAsync(Ct);
        var agent = await t.As("agent");
        var sub = await hooks.SubscribeAsync(agent, new SubscribeInput($"https://{Host}/decided", ["action.decided", "claim.expired"]), Ct);
        var a = await t.Broker.RequestAsync(agent, new ActionRequest("isolate_device",
            JsonSerializer.SerializeToElement(new { machine_id = TestBoard.Device }), "Webhook test: isolate for the decided event.", TestBoard.IncidentGraphId), Ct);
        await t.Broker.DecideAsync(await t.As("analyst"), a.Id, "deny", "not this time", Ct);

        var q = await t.Board.PostAsync(await t.As("analyst"), new PostInput("intel", "expiry webhook", "question"), ct: Ct);
        await t.Board.ClaimAsync(agent, q.Id, 30, Ct);
        // Expire the lease just now (after the subscription was created, so it counts).
        await using (var c = t.Db.Command("update messages set claim_expires_at = now() - interval '1 millisecond' where id = @id").With("id", q.Id))
            await c.ExecuteNonQueryAsync(Ct);

        await hooks.RunOnceAsync(Ct);
        await hooks.RunOnceAsync(Ct);
        Assert.Contains(rx.Got, g => g.Event.Event == "action.decided");
        Assert.Single(rx.Got, g => g.Event.Event == "claim.expired" && g.Event.MessageId == q.Id);
        await hooks.UnsubscribeAsync(agent, sub.Id, Ct);
    }

    [DbFact]
    public async Task Failing_receiver_is_retried_with_backoff_and_disabled_after_20_failures()
    {
        var (hooks, rx) = Hooks();
        rx.Status = HttpStatusCode.InternalServerError;
        await hooks.EnqueueAsync(Ct);
        var agent = await t.As("agent");
        var sub = await hooks.SubscribeAsync(agent, new SubscribeInput($"https://{Host}/broken", ["mention"]), Ct);
        await t.Board.PostAsync(await t.As("analyst"), new PostInput("general", "@agent ping for the failing receiver"), ct: Ct);
        await hooks.RunOnceAsync(Ct);
        Assert.Single(rx.Got);
        Assert.True(await t.ScalarAsync("select count(*) from webhook_deliveries where subscription_id = @s and status = 'pending' and next_attempt_at > now()", ("s", sub.Id)) == 1);
        await hooks.RunOnceAsync(Ct); // backoff: not due yet, so no second attempt
        Assert.Single(rx.Got);

        await using (var c = t.Db.Command("update agent_subscriptions set failures = 19 where id = @s; update webhook_deliveries set next_attempt_at = now() where subscription_id = @s").With("s", sub.Id))
            await c.ExecuteNonQueryAsync(Ct);
        await hooks.RunOnceAsync(Ct);
        Assert.Equal(0, await t.ScalarAsync("select count(*) from agent_subscriptions where id = @s and enabled", ("s", sub.Id)));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'webhook.disabled' and subject = @s", ("s", sub.Id.ToString())));
    }

    [DbFact]
    public async Task Followup_fires_once_across_instances_and_mentions_the_agent()
    {
        var agent = await t.As("agent");
        var q = await t.Board.PostAsync(await t.As("analyst"), new PostInput("containment", "isolation pending on ws-042", "question"), ct: Ct);
        var (a, _) = Hooks();
        var (b, _) = Hooks();
        var f = await a.ScheduleFollowupAsync(agent, new FollowupInput(q.Id, "check ws-042 isolation state", 1), Ct);
        Assert.Equal(0, await a.FireDueFollowupsAsync(Ct)); // not due yet
        await using (var c = t.Db.Command("update followups set due_at = now() - interval '1 second' where id = @id").With("id", f.Id))
            await c.ExecuteNonQueryAsync(Ct);
        // Two instances race; skip-locked claiming means the reminder is posted once.
        var fired = await Task.WhenAll(a.FireDueFollowupsAsync(Ct), b.FireDueFollowupsAsync(Ct));
        Assert.Equal(1, fired.Sum());
        var thread = await t.Board.GetThreadAsync(q.Id, Ct);
        var reminder = Assert.Single(thread.Replies, r => r.Type == "status");
        Assert.Contains("agent", reminder.Mentions);
        Assert.Contains("check ws-042 isolation state", reminder.Body);
        Assert.Equal(0, await a.FireDueFollowupsAsync(Ct));
    }
}
