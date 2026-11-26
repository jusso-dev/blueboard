using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Http;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Message notifications end to end: the sweep, settings, idempotency, quiet hours, and the settings routes.</summary>
public sealed class NotificationTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly string Secret = new('s', 40);

    private Notifier NewNotifier(Receiver rx) => new(new HttpClient(rx), t.Db, t.Audit, t.Ms, t.Settings with
    {
        NotifyWebhookUrl = "https://hooks.example.com/blueboard",
        NotifyWebhookSecret = Secret,
        NotifyAllowedHosts = ["hooks.example.com"],
        WebBaseUrl = "https://board.example.com",
    });

    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;

    private static List<JsonElement> Events(Receiver rx, Guid messageId) =>
        rx.Got.Select(g => JsonDocument.Parse(g.Body).RootElement).Where(e => e.TryGetProperty("message_id", out var m) && m.GetString() == messageId.ToString()).ToList();

    private static string[] Handles(JsonElement e) => e.GetProperty("recipients").EnumerateArray().Select(r => r.GetProperty("handle").GetString()!).ToArray();

    /// <summary>Starts the message cursor (the first sweep never replays history) and drains anything pending.</summary>
    private async Task PrimeAsync()
    {
        var n = NewNotifier(new Receiver());
        await n.RunOnceAsync(Ct);
        await n.RunOnceAsync(Ct);
    }

    private async Task<Message> Post(string who, string body, string type = "chat", object? payload = null, Guid? parent = null, string? incident = TestBoard.IncidentGraphId) =>
        await t.Board.PostAsync(await t.As(who), new PostInput("triage", body, type, payload is null ? null : JsonSerializer.SerializeToElement(payload), parent, incident), ct: Ct);

    [DbFact]
    public async Task First_run_does_not_replay_history()
    {
        await t.Db.Command("delete from kv_state where key = @k").With("k", Notifier.MessageCursorKey).ExecuteNonQueryAsync(Ct);
        var old = await Post("agent", "Anyone know who owns ws-042? (posted before notifications were on)", "question");
        var rx = new Receiver();
        Assert.Equal(0, await NewNotifier(rx).RunOnceAsync(Ct));
        Assert.Equal(0, await NewNotifier(rx).RunOnceAsync(Ct));
        Assert.Empty(Events(rx, old.Id));
        Assert.Equal(0, await t.ScalarAsync("select count(*) from notifications where message_id = @m", ("m", old.Id)));
        Assert.True(await t.ScalarAsync("select (value #>> '{}')::bigint from kv_state where key = @k", ("k", Notifier.MessageCursorKey)) >= long.Parse(old.Seq));
    }

    [DbFact]
    public async Task Agent_question_is_sent_once_across_sweeps_and_instances()
    {
        await PrimeAsync();
        var q = await Post("agent", "Is **ws-042** a jump host? I need to know before proposing [isolation](https://evil.example).\n\nSecond line.", "question");
        var rx = new Receiver();
        var sent = await Task.WhenAll(NewNotifier(rx).RunOnceAsync(Ct), NewNotifier(rx).RunOnceAsync(Ct));
        Assert.Equal(1, sent.Sum());
        Assert.Equal(0, await NewNotifier(rx).RunOnceAsync(Ct));

        var got = rx.Got.Single(g => g.Body.Contains(q.Id.ToString()));
        Assert.Equal(Notifier.Sign(got.Body, Secret), got.Signature);
        var e = JsonDocument.Parse(got.Body).RootElement;
        Assert.Equal("question", e.GetProperty("event").GetString());
        Assert.Equal("question", e.GetProperty("type").GetString());
        Assert.Equal("triage", e.GetProperty("channel").GetString());
        Assert.Equal("agent", e.GetProperty("author").GetProperty("handle").GetString());
        Assert.Equal("agent", e.GetProperty("author").GetProperty("kind").GetString());
        Assert.Equal(TestBoard.IncidentGraphId, e.GetProperty("incident").GetProperty("graph_id").GetString());
        Assert.Equal("high", e.GetProperty("incident").GetProperty("severity").GetString());
        Assert.Equal("Is ws-042 a jump host? I need to know before proposing isolation. Second line.", e.GetProperty("summary").GetString());
        Assert.Equal($"https://board.example.com/channels/triage#m-{q.Id}", e.GetProperty("url").GetString());
        // Nobody mentioned: everyone subscribed (every enabled person; agents never).
        Assert.Equal(["analyst", "analyst2", "reader"], Handles(e));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from notifications where message_id = @m and event = 'question' and status = 'sent'", ("m", q.Id)));
    }

    [DbFact]
    public async Task A_persons_own_settings_can_turn_mentions_off()
    {
        await PrimeAsync();
        var n = NewNotifier(new Receiver());
        var me = await t.As("analyst2");
        try
        {
            var view = await n.PutMineAsync(me, J("""{"events":{"mention":false}}"""), Ct);
            Assert.False(view.Effective.Events.Mention);
            Assert.True(view.Defaults.Events.Mention);
            Assert.Equal("""{"events":{"mention":false}}""", view.Mine!.Value.GetRawText());

            var m = await Post("agent", "@analyst @analyst2 the download cradle came from bad.example");
            var rx = new Receiver();
            Assert.Equal(1, await NewNotifier(rx).RunOnceAsync(Ct));
            var e = Events(rx, m.Id).Single();
            Assert.Equal("mention", e.GetProperty("event").GetString());
            Assert.Equal(["analyst"], Handles(e));
            Assert.Equal(0, await t.ScalarAsync("select count(*) from notifications where message_id = @m and recipient = 'analyst2'", ("m", m.Id)));
            Assert.Equal(1, await t.ScalarAsync("""
                select count(*) from audit_log where event = 'notify.settings_changed' and actor_id = @p and detail->'changed' ? 'events.mention'
                """, ("p", me.Id)));
        }
        finally
        {
            Assert.Null((await n.PutMineAsync(me, J("null"), Ct)).Mine);
        }
    }

    [DbFact]
    public async Task Action_result_goes_to_the_person_who_instructed_it()
    {
        await PrimeAsync();
        var app = A1.Build(t, new Policy { ActOnInstruction = ["update_incident"] });
        var said = await t.Board.PostAsync(await t.As("analyst"), new PostInput("incidents", "@agent that was our pen test, resolve it as a false positive please", "chat", null, null, TestBoard.IncidentGraphId), ct: Ct);
        var a = await app.Broker.RequestAsync(await t.As("agent"), new ActionRequest("update_incident",
            A1.El(new { incident_id = TestBoard.IncidentGraphId, status = "resolved", classification = "falsePositive" }),
            "Analyst confirmed an approved penetration test; resolving as a false positive.", TestBoard.IncidentGraphId, OnBehalfOf: said.Id), Ct);
        Assert.Equal("succeeded", a.Status);
        var result = await t.ScalarAsync("select count(*) from messages where parent_id = @m and type = 'action_result'", ("m", a.RequestMessageId));
        Assert.Equal(1, result);

        var rx = new Receiver();
        await NewNotifier(rx).RunOnceAsync(Ct);
        var e = rx.Got.Select(g => JsonDocument.Parse(g.Body).RootElement).Single(x => x.GetProperty("event").GetString() == "action_result");
        Assert.Equal(["analyst"], Handles(e));
        Assert.Equal(a.Id.ToString(), e.GetProperty("action").GetProperty("id").GetString());
        Assert.Equal("succeeded", e.GetProperty("action").GetProperty("status").GetString());
        Assert.Equal(Catalog.Get("update_incident").Title, e.GetProperty("action").GetProperty("title").GetString());
        Assert.Equal(("board", "system"), (e.GetProperty("author").GetProperty("handle").GetString(), e.GetProperty("author").GetProperty("kind").GetString()));
        Assert.Equal($"https://board.example.com/channels/containment#m-{a.RequestMessageId}", e.GetProperty("url").GetString());
    }

    [DbFact]
    public async Task Verdicts_notify_for_true_positives_but_not_false_positives()
    {
        await PrimeAsync();
        var tp = await Post("agent", "Credential theft confirmed", "verdict", new { classification = "truePositive", confidence = 0.9 });
        var fp = await Post("agent2", "Benign admin script", "verdict", new { classification = "falsePositive", confidence = 0.8 });
        var rx = new Receiver();
        await NewNotifier(rx).RunOnceAsync(Ct);
        var e = Events(rx, tp.Id).Single();
        Assert.Equal("verdict", e.GetProperty("event").GetString());
        Assert.Equal("truePositive", e.GetProperty("classification").GetString());
        Assert.Equal(0.9, e.GetProperty("confidence").GetDouble());
        Assert.Empty(Events(rx, fp.Id));
    }

    [DbFact]
    public async Task Quiet_hours_hold_a_notice_until_the_window_ends()
    {
        await PrimeAsync();
        var n = NewNotifier(new Receiver());
        var me = await t.As("analyst");
        var now = DateTimeOffset.UtcNow;
        // A window around now in UTC; the incident is high severity, so except_high_severity must be off to hold.
        var start = now.AddHours(-1).ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture);
        var end = now.AddHours(1).ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture);
        try
        {
            await n.PutMineAsync(me, J(Json.Serialize(new { quiet_hours = new { enabled = true, start, end, time_zone = "UTC", except_high_severity = false } })), Ct);
            var m = await Post("agent", "@analyst can you check the proxy logs for bad.example?", "question");
            var rx = new Receiver();
            Assert.Equal(0, await NewNotifier(rx).RunOnceAsync(Ct));
            Assert.Empty(Events(rx, m.Id));
            Assert.Equal(1, await t.ScalarAsync("select count(*) from notifications where message_id = @m and recipient = 'analyst' and status = 'held' and send_after > now()", ("m", m.Id)));

            await t.Db.Command("update notifications set send_after = now() - interval '1 second' where message_id = @m").With("m", m.Id).ExecuteNonQueryAsync(Ct);
            Assert.Equal(1, await NewNotifier(rx).RunOnceAsync(Ct));
            Assert.Equal("question", Events(rx, m.Id).Single().GetProperty("event").GetString());
            Assert.Equal(0, await NewNotifier(rx).RunOnceAsync(Ct));
            Assert.Equal(1, await t.ScalarAsync("select count(*) from notifications where message_id = @m and status = 'sent'", ("m", m.Id)));
        }
        finally
        {
            await n.PutMineAsync(me, J("null"), Ct);
        }
    }

    [DbFact]
    public async Task Settings_routes_validate_and_guard_defaults()
    {
        var rx = new Receiver();
        var notifier = NewNotifier(rx);
        var app = A1.Build(t, new Policy());
        var setup = new Setup(t.Db, t.Settings, new Policy(), t.Ms, notifier);
        var ops = new OpsApi(new Endpoint(app.Auth, Microsoft.Extensions.Logging.Abstractions.NullLogger<Endpoint>.Instance), setup, notifier,
            new Participants(t.Db, t.Audit, t.Board, t.System), app.Broker, new AuditLog(t.Db, t.Audit), new Posture(t.Db, t.Settings, new Policy()));

        var (status, body) = A1.Read(await ops.GetNotificationSettings(A1.Request("reader")));
        Assert.Equal(200, status);
        Assert.Equal(["defaults", "mine", "effective", "sinks", "can_edit_defaults"], body.EnumerateObject().Select(p => p.Name));
        Assert.False(body.GetProperty("can_edit_defaults").GetBoolean());
        Assert.DoesNotContain("hooks.example.com", body.GetRawText());
        var webhook = body.GetProperty("sinks").EnumerateArray().Single(s => s.GetProperty("sink").GetString() == "webhook");
        Assert.True(webhook.GetProperty("configured").GetBoolean() && webhook.GetProperty("ready").GetBoolean());
        Assert.False(body.GetProperty("sinks").EnumerateArray().Single(s => s.GetProperty("sink").GetString() == "teams").GetProperty("configured").GetBoolean());

        Assert.Equal(400, A1.Read(await ops.PutMyNotificationSettings(A1.Request("reader", "PUT", new { evnts = new { mention = false } }))).Status);
        Assert.Equal(400, A1.Read(await ops.PutMyNotificationSettings(A1.Request("reader", "PUT", new { quiet_hours = new { time_zone = "Nowhere/Land" } }))).Status);
        Assert.Equal(403, A1.Read(await ops.PutDefaultNotificationSettings(A1.Request("analyst2", "PUT", new { events = new { finding = true } }))).Status);
        Assert.Equal(403, A1.Read(await ops.GetNotificationSettings(A1.Request("agent"))).Status); // people only

        var (ok, defaults) = A1.Read(await ops.PutDefaultNotificationSettings(A1.Request("analyst", "PUT", new { events = new { finding = true }, min_incident_severity = "medium" })));
        Assert.Equal(200, ok);
        Assert.True(defaults.GetProperty("defaults").GetProperty("events").GetProperty("finding").GetBoolean());
        Assert.Equal("medium", defaults.GetProperty("effective").GetProperty("min_incident_severity").GetString());
        Assert.True(defaults.GetProperty("can_edit_defaults").GetBoolean());
        var reset = A1.Read(await ops.PutDefaultNotificationSettings(A1.Request("analyst", "PUT", new { events = new { finding = (bool?)null }, min_incident_severity = (string?)null }))).Body;
        Assert.False(reset.GetProperty("defaults").GetProperty("events").GetProperty("finding").GetBoolean());
        Assert.Equal(0, await t.ScalarAsync("select count(*) from notification_settings where principal_id is null"));

        // A test notice to yourself, marked as a test.
        var (ts, results) = A1.Read(await ops.TestNotifications(A1.Request("reader", "POST", new { @event = "question" })));
        Assert.Equal(200, ts);
        Assert.Equal("webhook", results.EnumerateArray().Single().GetProperty("sink").GetString());
        var sample = JsonDocument.Parse(rx.Got.Last().Body).RootElement;
        Assert.True(sample.GetProperty("test").GetBoolean());
        Assert.Equal(["reader"], Handles(sample));
        Assert.Equal(400, A1.Read(await ops.TestNotifications(A1.Request("reader", "POST", new { @event = "bogus" }))).Status);
        Assert.Equal(429, A1.Read(await ops.TestNotifications(A1.Request("reader", "POST", new { @event = "verdict" }))).Status);

        Assert.Equal(403, A1.Read(await ops.RecentNotifications(A1.Request("reader", query: "?limit=5"))).Status);
        var (rs, recent) = A1.Read(await ops.RecentNotifications(A1.Request("analyst", query: "?limit=5")));
        Assert.Equal(200, rs);
        Assert.True(recent.GetArrayLength() <= 5);
        Assert.All(recent.EnumerateArray(), r => Assert.Equal(["event", "sink", "status", "error", "recipient", "created_at", "message_id", "action_id"], r.EnumerateObject().Select(p => p.Name)));

        // The setup page's old test button still works.
        Assert.Equal(200, A1.Read(await ops.TestNotification(A1.Request("analyst", "POST"))).Status);
    }

    // ── ntfy (phone push) ──────────────────────────────────────────────────────────────────────────
    private const string NtfyToken = "tk_faketoken0000000000000000000";

    private Notifier NtfyNotifier(Receiver rx) => new(new HttpClient(rx), t.Db, t.Audit, t.Ms, t.Settings with
    {
        NotifyNtfyUrl = "http://ntfy:8080/blueboard",
        NotifyNtfyToken = NtfyToken,
        NotifyAllowedHosts = ["ntfy"],
        WebBaseUrl = "https://board.example.com",
    });

    [DbFact]
    public async Task Ntfy_gets_a_json_publish_to_the_server_root_with_the_token()
    {
        await PrimeAsync();
        await NtfyNotifier(new Receiver()).RunOnceAsync(Ct); // drain anything another test left for this sink
        var q = await Post("agent", "@analyst is **ws-042** a jump host?\nSecond line.", "question");
        var rx = new Receiver();
        Assert.Equal(1, await NtfyNotifier(rx).RunOnceAsync(Ct));
        Assert.Equal(0, await NtfyNotifier(rx).RunOnceAsync(Ct));

        var got = rx.Got.Single();
        Assert.Equal("http://ntfy:8080/", got.Uri.ToString()); // the root, not the topic URL
        Assert.Equal(NtfyToken, got.Auth);
        Assert.Null(got.Signature);
        var e = JsonDocument.Parse(got.Body).RootElement;
        Assert.Equal(["topic", "title", "message", "priority", "tags", "click"], e.EnumerateObject().Select(p => p.Name));
        Assert.Equal("blueboard", e.GetProperty("topic").GetString());
        Assert.Equal("@agent needs your input", e.GetProperty("title").GetString());
        Assert.Equal(4, e.GetProperty("priority").GetInt32());
        Assert.Equal("question", e.GetProperty("tags")[0].GetString());
        Assert.Equal($"https://board.example.com/channels/triage#m-{q.Id}", e.GetProperty("click").GetString());
        Assert.Contains("Summary: @analyst is ws-042 a jump host? Second line.", e.GetProperty("message").GetString());
        Assert.Equal(1, await t.ScalarAsync("select count(*) from notifications where message_id = @m and sink = 'ntfy' and status = 'sent'", ("m", q.Id)));

        var last = await NtfyNotifier(rx).LastDeliveryAsync(Ct);
        Assert.Equal("sent", last["ntfy"].Status);
    }

    [DbFact]
    public async Task Ntfy_can_be_turned_off_per_person_and_failures_keep_secrets_out()
    {
        await PrimeAsync();
        await NtfyNotifier(new Receiver()).RunOnceAsync(Ct);
        var n = NtfyNotifier(new Receiver());
        var me = await t.As("analyst");
        try
        {
            var view = await n.PutMineAsync(me, J("""{"sinks":{"ntfy":false}}"""), Ct);
            Assert.False(view.Effective.Sinks.Ntfy);
            Assert.True(view.Effective.Sinks.Webhook);
            var status = view.Sinks.Single(s => s.Sink == "ntfy");
            Assert.True(status.Configured && status.Ready);
            Assert.DoesNotContain("ntfy:8080", Json.Serialize(view));
            Assert.DoesNotContain(NtfyToken, Json.Serialize(view));

            var m = await Post("agent", "@analyst please check the proxy logs", "question");
            var rx = new Receiver();
            Assert.Equal(0, await NtfyNotifier(rx).RunOnceAsync(Ct));
            Assert.Empty(rx.Got);
        }
        finally
        {
            await n.PutMineAsync(me, J("null"), Ct);
        }

        var failing = new Receiver { Status = System.Net.HttpStatusCode.Forbidden };
        var m2 = await Post("agent", "@analyst one more question", "question");
        Assert.Equal(0, await NtfyNotifier(failing).RunOnceAsync(Ct));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from notifications where message_id = @m and sink = 'ntfy' and status = 'failed' and error = 'HTTP 403'", ("m", m2.Id)));
        Assert.Equal(0, await t.ScalarAsync("select count(*) from audit_log where event = 'notify.failed' and (detail::text like '%ntfy:8080%' or strpos(detail::text, 'tk_faketoken') > 0)"));
        Assert.Equal("failed", (await NtfyNotifier(failing).LastDeliveryAsync(Ct))["ntfy"].Status);
    }

    [DbFact]
    public async Task Sink_constraint_accepts_ntfy_and_refuses_unknown_sinks()
    {
        var a = await t.ScalarAsync("select count(*) from pg_constraint where conname = 'notifications_sink_check' and pg_get_constraintdef(oid) like '%ntfy%'");
        Assert.Equal(1, a);
        await Assert.ThrowsAsync<Npgsql.PostgresException>(async () =>
            await t.Db.Command("insert into notifications (message_id, event, sink) select id, 'x', 'slack' from messages limit 1").ExecuteNonQueryAsync(Ct));
    }
}
