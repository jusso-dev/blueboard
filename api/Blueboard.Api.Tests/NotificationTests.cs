using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Http;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Notification settings, quiet hours, which messages notify whom, and the message-event payload.</summary>
public class NotificationTests
{
    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;
    private static readonly NotificationSettings D = NotificationRules.BuiltIn;

    private static Person P(string handle, Func<NotificationSettings, NotificationSettings>? f = null, bool approver = false) =>
        new(handle, handle.ToUpperInvariant(), $"{handle}@contoso.com", approver ? ["poster", "approver"] : ["poster"], (f ?? (s => s))(D));

    private static MessageFacts M(string type = "chat", string author = "agent", string kind = "agent", string[]? mentions = null, Guid? parent = null,
        string? severity = null, string? classification = null, string[]? thread = null, string[]? action = null) =>
        new(Guid.NewGuid(), type, author, kind, mentions ?? [], parent, severity, classification, thread ?? [], action ?? []);

    private static NotificationSettings Events(NotificationSettings s, Func<NotificationEventToggles, NotificationEventToggles> f) => s with { Events = f(s.Events) };

    // ── settings validation and merge ────────────────────────────────────────────────────────────
    [Fact]
    public void Built_in_defaults_match_the_documented_shape()
    {
        var json = JsonNode.Parse(Json.Serialize(D))!.AsObject();
        Assert.Equal(["enabled", "events", "verdict_classifications", "min_incident_severity", "mentions_from_people", "include_summary", "quiet_hours", "sinks"], json.Select(kv => kv.Key));
        Assert.Equal(NotificationRules.EventKeys, json["events"]!.AsObject().Select(kv => kv.Key));
        Assert.Equal(["truePositive", "unknown"], D.VerdictClassifications);
        Assert.False(D.Events.Finding);
        Assert.False(D.Events.Incident);
        Assert.True(D.Events.ActionResult);
        Assert.Equal("high", D.MinIncidentSeverity);
        // The defaults themselves pass strict validation.
        NotificationRules.ValidatePatch(Json.Element(D), allowNull: false);
    }

    [Theory]
    [InlineData("""{"enabeld":true}""", "unknown notification setting enabeld")]
    [InlineData("""{"events":{"mentions":true}}""", "unknown notification setting events.mentions")]
    [InlineData("""{"events":true}""", "events must be an object")]
    [InlineData("""{"enabled":"yes"}""", "enabled must be true or false")]
    [InlineData("""{"quiet_hours":{"start":"7:00"}}""", "quiet_hours.start must be a time as HH:mm")]
    [InlineData("""{"quiet_hours":{"end":"24:00"}}""", "quiet_hours.end must be a time")]
    [InlineData("""{"quiet_hours":{"time_zone":"Mars/Olympus"}}""", "quiet_hours.time_zone must be an IANA time zone")]
    [InlineData("""{"quiet_hours":{"time_zone":"../../etc/passwd"}}""", "IANA")]
    [InlineData("""{"min_incident_severity":"critical"}""", "min_incident_severity must be one of")]
    [InlineData("""{"verdict_classifications":["malicious"]}""", "verdict_classifications must list distinct values")]
    [InlineData("""{"verdict_classifications":["unknown","unknown"]}""", "distinct")]
    [InlineData("""{"verdict_classifications":"truePositive"}""", "must be a list")]
    [InlineData("""{"sinks":{"slack":true}}""", "unknown notification setting sinks.slack")]
    [InlineData("""[1]""", "must be a JSON object")]
    public void Settings_are_validated_strictly(string json, string message)
    {
        var ex = Assert.Throws<BoardException>(() => NotificationRules.ValidatePatch(J(json)));
        Assert.Equal(400, ex.Status);
        Assert.Contains(message, ex.Message);
    }

    [Fact]
    public void Null_resets_only_where_allowed()
    {
        NotificationRules.ValidatePatch(J("""{"events":{"mention":null},"quiet_hours":null}"""));
        Assert.Throws<BoardException>(() => NotificationRules.ValidatePatch(J("""{"enabled":null}"""), allowNull: false));
    }

    [Fact]
    public void Patches_merge_field_by_field_and_null_resets()
    {
        var stored = NotificationRules.ApplyPatch(null, NotificationRules.ValidatePatch(J("""{"events":{"mention":false,"reply":false},"quiet_hours":{"enabled":true,"time_zone":"Europe/London"}}""")));
        var next = NotificationRules.ApplyPatch(stored, NotificationRules.ValidatePatch(J("""{"events":{"reply":null},"quiet_hours":{"enabled":null,"time_zone":null},"verdict_classifications":["truePositive"]}""")));
        Assert.Equal("""{"events":{"mention":false},"verdict_classifications":["truePositive"]}""", next.ToJsonString());

        var effective = NotificationRules.Effective(D, next);
        Assert.False(effective.Events.Mention);
        Assert.True(effective.Events.Reply);               // reset: back to the default
        Assert.Equal(["truePositive"], effective.VerdictClassifications); // arrays replace, never merge
        Assert.Equal(D.QuietHours, effective.QuietHours);
        Assert.Equal(["events.reply", "quiet_hours.enabled", "quiet_hours.time_zone", "verdict_classifications"], NotificationRules.Paths(NotificationRules.ValidatePatch(J("""{"events":{"reply":null},"quiet_hours":{"enabled":null,"time_zone":null},"verdict_classifications":["truePositive"]}"""))));
    }

    [Fact]
    public void Board_default_include_summary_is_a_ceiling()
    {
        var mine = NotificationRules.ValidatePatch(J("""{"include_summary":true}"""));
        Assert.True(NotificationRules.Effective(D, mine).IncludeSummary);
        Assert.False(NotificationRules.Effective(D with { IncludeSummary = false }, mine).IncludeSummary);
    }

    // ── quiet hours ──────────────────────────────────────────────────────────────────────────────
    private static readonly QuietHours Overnight = new(true, "22:00", "07:00", "Australia/Sydney", true);

    [Theory]
    // Sydney is UTC+11 in January (daylight saving) and UTC+10 in July.
    [InlineData("2027-01-15T10:59:00Z", null)]                       // 21:59 local: not yet
    [InlineData("2027-01-15T11:00:00Z", "2027-01-15T20:00:00Z")]     // 22:00 local → 07:00 next morning
    [InlineData("2027-01-15T15:30:00Z", "2027-01-15T20:00:00Z")]     // 02:30 local, after midnight
    [InlineData("2027-01-15T20:00:00Z", null)]                       // 07:00 local: over
    [InlineData("2027-07-15T12:00:00Z", "2027-07-15T21:00:00Z")]     // 22:00 AEST (UTC+10) → 07:00 AEST
    public void Overnight_quiet_hours_follow_the_time_zone(string now, string? until)
    {
        var got = NotificationRules.QuietUntil(Overnight, DateTimeOffset.Parse(now, System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(until is null ? null : DateTimeOffset.Parse(until, System.Globalization.CultureInfo.InvariantCulture), got);
    }

    [Fact]
    public void Daytime_window_disabled_and_empty_windows()
    {
        var day = new QuietHours(true, "09:00", "17:00", "UTC", false);
        Assert.Equal(DateTimeOffset.Parse("2027-03-01T17:00:00Z"), NotificationRules.QuietUntil(day, DateTimeOffset.Parse("2027-03-01T12:00:00Z")));
        Assert.Null(NotificationRules.QuietUntil(day, DateTimeOffset.Parse("2027-03-01T08:59:00Z")));
        Assert.Null(NotificationRules.QuietUntil(day with { Enabled = false }, DateTimeOffset.Parse("2027-03-01T12:00:00Z")));
        Assert.Null(NotificationRules.QuietUntil(day with { End = "09:00" }, DateTimeOffset.Parse("2027-03-01T12:00:00Z")));
    }

    [Fact]
    public void Quiet_hours_hold_unless_the_incident_is_high_severity()
    {
        var night = DateTimeOffset.Parse("2027-01-15T15:30:00Z"); // 02:30 in Sydney
        var sleepy = P("ana", s => s with { QuietHours = Overnight });
        var events = NotificationRules.Events(M("question", mentions: ["ana"]), [sleepy]);
        var held = NotificationRules.Route(events, ["webhook"], D, "medium", night).Single();
        Assert.Equal(DateTimeOffset.Parse("2027-01-15T20:00:00Z"), held.HoldUntil);
        Assert.Null(NotificationRules.Route(events, ["webhook"], D, "high", night).Single().HoldUntil);
        var strict = P("ana", s => s with { QuietHours = Overnight with { ExceptHighSeverity = false } });
        Assert.NotNull(NotificationRules.Route(NotificationRules.Events(M("question", mentions: ["ana"]), [strict]), ["webhook"], D, "high", night).Single().HoldUntil);
    }

    [Fact]
    public void Board_wide_notice_splits_sleepers_into_held_per_person_notices()
    {
        var night = DateTimeOffset.Parse("2027-01-15T15:30:00Z");
        var people = new[] { P("ana", s => s with { QuietHours = Overnight }), P("bob") };
        var plan = NotificationRules.Route(NotificationRules.Events(M("question"), people), ["webhook"], D, null, night);
        var now = plan.Single(p => p.HoldUntil is null);
        Assert.Null(now.Recipient);
        Assert.Equal(["bob"], now.To.Select(x => x.Handle));
        var later = plan.Single(p => p.HoldUntil is not null);
        Assert.Equal("ana", later.Recipient);
    }

    // ── which events, for whom ───────────────────────────────────────────────────────────────────
    private static IEnumerable<(string Event, string? Recipient, string To)> Ev(MessageFacts m, params Person[] people) =>
        NotificationRules.Events(m, people).Select(e => (e.Event, e.Recipient, string.Join(",", e.To.Select(p => p.Handle))));

    [Fact]
    public void Agent_question_mentioning_a_person_is_for_them_only()
    {
        Assert.Equal([("question", "ana", "ana")], Ev(M("question", mentions: ["ana", "agent2"]), P("ana"), P("bob")));
    }

    [Fact]
    public void Agent_question_with_no_one_mentioned_goes_to_everyone_subscribed()
    {
        Assert.Equal([("question", null, "ana,bob")], Ev(M("question"), P("ana"), P("bob"), P("cy", s => Events(s, e => e with { Question = false }))));
        // Nobody subscribed: nothing.
        Assert.Empty(Ev(M("question"), P("cy", s => Events(s, e => e with { Question = false }))));
    }

    [Fact]
    public void Question_addressed_to_someone_who_opted_out_is_not_broadcast()
    {
        Assert.Empty(Ev(M("question", mentions: ["ana"]), P("ana", s => s with { Enabled = false }), P("bob")));
    }

    [Fact]
    public void Mentions_from_people_only_when_asked_for()
    {
        Assert.Empty(Ev(M("chat", author: "bob", kind: "human", mentions: ["ana"]), P("ana"), P("bob")));
        Assert.Equal([("mention", "ana", "ana")], Ev(M("chat", author: "bob", kind: "human", mentions: ["ana"]), P("ana", s => s with { MentionsFromPeople = true }), P("bob")));
        Assert.Equal([("mention", "ana", "ana")], Ev(M("chat", mentions: ["ana"]), P("ana")));
        Assert.Empty(Ev(M("chat", mentions: ["ana"]), P("ana", s => Events(s, e => e with { Mention = false }))));
    }

    [Fact]
    public void Question_falls_back_to_mention_when_question_is_off()
    {
        Assert.Equal([("mention", "ana", "ana")], Ev(M("question", mentions: ["ana"]), P("ana", s => Events(s, e => e with { Question = false }))));
    }

    [Fact]
    public void Replies_in_a_persons_thread_unless_already_told()
    {
        var root = Guid.NewGuid();
        Assert.Equal([("reply", "ana", "ana"), ("reply", "bob", "bob")], Ev(M("chat", parent: root, thread: ["bob", "ana"]), P("ana"), P("bob")));
        // ana is mentioned too: she gets the mention, not also a reply.
        Assert.Equal([("mention", "ana", "ana"), ("reply", "bob", "bob")], Ev(M("chat", parent: root, mentions: ["ana"], thread: ["ana", "bob"]), P("ana"), P("bob")));
        // A person's own reply never notifies them, and a person replying doesn't produce "reply" events.
        Assert.Empty(Ev(M("chat", author: "ana", kind: "human", parent: root, thread: ["ana", "bob"]), P("ana"), P("bob")));
        // Top-level messages have no thread.
        Assert.Empty(Ev(M("chat", thread: ["ana"]), P("ana")));
    }

    [Fact]
    public void Verdicts_notify_for_the_subscribed_classifications()
    {
        Assert.Equal([("verdict", null, "ana")], Ev(M("verdict", classification: "truePositive"), P("ana")));
        Assert.Equal([("verdict", null, "ana")], Ev(M("verdict", classification: "unknown"), P("ana")));
        Assert.Empty(Ev(M("verdict", classification: "falsePositive"), P("ana")));
        Assert.Empty(Ev(M("verdict", classification: "informationalExpectedActivity"), P("ana")));
        Assert.Equal([("verdict", null, "ana")], Ev(M("verdict", classification: "falsePositive"), P("ana", s => s with { VerdictClassifications = ["falsePositive"] })));
        // A person's own verdict (or one posted by a person) isn't "an agent found something".
        Assert.Empty(Ev(M("verdict", author: "bob", kind: "human", classification: "truePositive"), P("ana")));
    }

    [Fact]
    public void Findings_and_incidents_are_off_by_default_and_respect_severity()
    {
        Assert.Empty(Ev(M("finding", severity: "high"), P("ana")));
        var on = P("ana", s => Events(s, e => e with { Finding = true, Incident = true }) with { MinIncidentSeverity = "medium" });
        Assert.Equal([("finding", null, "ana")], Ev(M("finding", severity: "high"), on));
        Assert.Equal([("finding", null, "ana")], Ev(M("finding", severity: "medium"), on));
        Assert.Empty(Ev(M("finding", severity: "low"), on));
        Assert.Empty(Ev(M("finding"), on)); // not on an incident
        Assert.Equal([("incident", null, "ana")], Ev(M("incident", author: "board", kind: "system", severity: "high"), on));
        Assert.Empty(Ev(M("incident", author: "board", kind: "system", severity: "low"), on));
        // An agent can't post type incident, and an incident update in a thread isn't a new incident.
        Assert.Empty(Ev(M("incident", severity: "high"), on));
        Assert.Empty(Ev(M("incident", author: "board", kind: "system", severity: "high", parent: Guid.NewGuid()), on));
    }

    [Fact]
    public void Action_results_go_to_the_person_who_asked()
    {
        var root = Guid.NewGuid();
        var m = M("action_result", author: "board", kind: "system", parent: root, thread: ["bob"], action: ["ana"]);
        Assert.Equal([("action_result", "ana", "ana")], Ev(m, P("ana"), P("bob")));
        Assert.Empty(Ev(m, P("ana", s => Events(s, e => e with { ActionResult = false }))));
        // Only the board's own results count: an agent can't post one.
        Assert.Empty(Ev(M("action_result", action: ["ana"]), P("ana")));
    }

    [Fact]
    public void Turning_notifications_off_silences_everything_and_sinks_filter()
    {
        var off = P("ana", s => s with { Enabled = false });
        Assert.Empty(Ev(M("question", mentions: ["ana"]), off));
        var webhookOnly = P("ana", s => s with { Sinks = new(true, false, false) });
        var plan = NotificationRules.Route(NotificationRules.Events(M("question", mentions: ["ana"]), [webhookOnly]), ["webhook", "teams", "mail"], D, null, DateTimeOffset.UtcNow);
        Assert.Equal(["webhook"], plan.Select(p => p.Sink));
    }

    [Fact]
    public void Approval_notices_follow_approvers_settings()
    {
        var now = DateTimeOffset.Parse("2027-01-15T15:30:00Z"); // 02:30 in Sydney
        // No approver has signed in: the board default decides (as before).
        Assert.True(NotificationRules.Approvals([P("ana")], D, "webhook", null, now).Send);
        Assert.False(NotificationRules.Approvals([], Events(D, e => e with { Approvals = false }), "webhook", null, now).Send);
        var r = NotificationRules.Approvals([P("ana", approver: true), P("bob", s => Events(s, e => e with { Approvals = false }), approver: true)], D, "webhook", null, now);
        Assert.Equal((true, "ana", (DateTimeOffset?)null), (r.Send, string.Join(",", r.To.Select(p => p.Handle)), r.HoldUntil));
        Assert.False(NotificationRules.Approvals([P("bob", s => Events(s, e => e with { Approvals = false }), approver: true)], D, "webhook", null, now).Send);
        // Everyone who wants it is asleep: held until the first window ends; a high-severity incident goes now.
        var sleepy = P("ana", s => s with { QuietHours = Overnight }, approver: true);
        Assert.Equal(DateTimeOffset.Parse("2027-01-15T20:00:00Z"), NotificationRules.Approvals([sleepy], D, "webhook", "medium", now).HoldUntil);
        Assert.Null(NotificationRules.Approvals([sleepy], D, "webhook", "high", now).HoldUntil);
    }

    // ── payload ──────────────────────────────────────────────────────────────────────────────────
    [Fact]
    public void Summary_is_one_plain_capped_line()
    {
        var body = "## Found it\n\n**Credential theft** on [ws-042](https://evil.example/x) <img src=x onerror=alert(1)>\n```\nrm -rf /\n```\n- one\n- two snake_case_name " + new string('x', 400);
        var s = NotificationRules.Summary(body);
        Assert.True(s.Length <= 280);
        Assert.EndsWith("…", s);
        Assert.StartsWith("Found it Credential theft on ws-042 [code] one two snake_case_name", s);
        Assert.DoesNotContain("evil.example", s);
        Assert.DoesNotContain("<img", s);
        Assert.DoesNotContain("\n", s);
        Assert.DoesNotContain("rm -rf", s);
        Assert.Equal("short", NotificationRules.Summary("short"));
        Assert.Equal("a b", NotificationRules.Summary("a‮\nb"));
    }

    private static MessageNotice Sample(string summary = "**Credential theft** on [ws-042](https://evil.example)") =>
        new("verdict", Guid.Parse("11111111-2222-3333-4444-555555555555"), "triage", new Author("enrichment-agent", "Enrichment <b>agent</b>", "agent"), "verdict",
            NotificationRules.Summary(summary), "90210", "[x](https://evil.example) title", "high", "truePositive", 0.92, null,
            [new NotificationRecipient("ana", "Ana Lopez", "ana@contoso.com"), new NotificationRecipient("bob", "Bob")],
            "https://board.example/channels/triage#m-11111111-2222-3333-4444-555555555555");

    [Fact]
    public void Message_event_payload_shape()
    {
        var json = JsonNode.Parse(Json.Serialize(Notifier.WebhookPayload(Sample())))!.AsObject();
        Assert.Equal(["event", "message_id", "incident", "channel", "author", "type", "summary", "classification", "confidence", "recipients", "url", "test", "sent_at"], json.Select(kv => kv.Key));
        Assert.Equal("verdict", json["event"]!.GetValue<string>());
        Assert.Equal("Credential theft on ws-042", json["summary"]!.GetValue<string>());
        Assert.Equal(0.92, json["confidence"]!.GetValue<double>());
        Assert.Equal(["graph_id", "title", "severity"], json["incident"]!.AsObject().Select(kv => kv.Key));
        Assert.Equal(["handle", "display_name", "kind"], json["author"]!.AsObject().Select(kv => kv.Key));
        var recipients = json["recipients"]!.AsArray();
        Assert.Equal("ana@contoso.com", recipients[0]!["email"]!.GetValue<string>());
        Assert.False(recipients[1]!.AsObject().ContainsKey("email")); // no address known: left out
        Assert.Equal("https://board.example/channels/triage#m-11111111-2222-3333-4444-555555555555", json["url"]!.GetValue<string>());
        Assert.False(json["test"]!.GetValue<bool>());

        // include_summary off: summary is null, never the body.
        var quiet = JsonNode.Parse(Json.Serialize(Notifier.WebhookPayload(Sample() with { Summary = null, Classification = null, Confidence = null, Event = "question", Type = "question" })))!.AsObject();
        Assert.Null(quiet["summary"]);
        Assert.False(quiet.ContainsKey("classification"));
        Assert.False(quiet.ContainsKey("confidence"));
    }

    [Fact]
    public void Approval_payload_is_unchanged_apart_from_recipients()
    {
        var n = new Notice("action.pending_approval", Guid.NewGuid(), "Isolate device (MDE)", "ws-042", "agent", "90210", "t", "high", 1, "https://b/approvals#x", "pending_approval",
            [new NotificationRecipient("ana", "Ana", "ana@contoso.com")]);
        var json = JsonNode.Parse(Json.Serialize(Notifier.WebhookPayload(n)))!.AsObject();
        Assert.Equal(["event", "action_id", "status", "title", "target", "requested_by", "incident", "policy_notes", "recipients", "url", "sent_at"], json.Select(kv => kv.Key));
        Assert.Equal("ana", json["recipients"]![0]!["handle"]!.GetValue<string>());
    }

    [Fact]
    public void Message_event_signature_is_hmac_over_the_raw_body()
    {
        var body = Json.Serialize(Notifier.WebhookPayload(Sample()));
        var secret = new string('k', 40);
        Assert.Equal("sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body))), Notifier.Sign(body, secret));
    }

    [Theory]
    [InlineData("question", "@enrichment-agent needs your input")]
    [InlineData("mention", "@enrichment-agent mentioned you")]
    [InlineData("reply", "@enrichment-agent replied in your thread")]
    [InlineData("verdict", "True positive verdict on incident 90210")]
    [InlineData("finding", "Finding on incident 90210")]
    [InlineData("incident", "New high severity incident 90210")]
    public void Headlines_for_message_events(string evt, string headline) =>
        Assert.Equal(headline, Notifier.Headline(Sample() with { Event = evt }));

    [Fact]
    public void Action_result_headline() =>
        Assert.Equal("Action failed: Update incident", Notifier.Headline(Sample() with { Event = "action_result", Action = new NoticeAction(Guid.NewGuid(), "Update incident", "failed") }));

    [Fact]
    public void Teams_and_mail_escape_message_events()
    {
        var hostile = Sample("[click](https://evil.example) <img src=x onerror=alert(1)> **bold** ${{secret}}") with { Summary = "[click](https://evil.example) <img src=x onerror=alert(1)> ${{secret}}" };
        var card = Json.Serialize(Notifier.TeamsCard(hostile));
        var doc = JsonDocument.Parse(card);
        var content = doc.RootElement.GetProperty("attachments")[0].GetProperty("content");
        var texts = content.GetProperty("body").EnumerateArray()
            .SelectMany(b => b.TryGetProperty("facts", out var f) ? f.EnumerateArray().Select(x => x.GetProperty("value").GetString()!) : [b.GetProperty("text").GetString()!]).ToList();
        Assert.All(texts, t => Assert.DoesNotMatch(@"(?<!\\)\[[^\]]*(?<!\\)\]\(", t));
        Assert.Contains(texts, t => t.Contains(@"\[click\]\(https://evil\.example\)"));
        Assert.DoesNotContain(texts, t => t.Contains("${{"));
        Assert.Equal(hostile.Url, content.GetProperty("actions")[0].GetProperty("url").GetString());

        var html = Notifier.MailHtml(hostile);
        Assert.DoesNotContain("<img", html);
        Assert.DoesNotContain("<b>", html);
        Assert.Contains("&lt;img src=x onerror=alert(1)&gt;", html);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(html, "<a "));
    }

    [Fact]
    public void Message_links_match_the_web_permalink()
    {
        var n = new Notifier(new HttpClient(), new Blueboard.Api.Data.Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" }), null!, null!,
            new Settings { WebBaseUrl = "https://board.example.com/" });
        var id = Guid.NewGuid();
        Assert.Equal($"https://board.example.com/channels/triage#m-{id}", n.MessageLink("triage", id));
        Assert.Null(new Notifier(new HttpClient(), new Blueboard.Api.Data.Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" }), null!, null!,
            new Settings { WebBaseUrl = "http://board.example.com" }).MessageLink("triage", id));
    }

    [Fact]
    public void Openapi_lists_the_notification_routes()
    {
        var paths = OpenApi.Document()["paths"]!.AsObject();
        Assert.NotNull(paths["/api/notifications/settings"]!["get"]);
        Assert.NotNull(paths["/api/notifications/settings/mine"]!["put"]);
        Assert.Equal("admin", paths["/api/notifications/settings/defaults"]!["put"]!["x-board-role"]!.GetValue<string>());
        Assert.NotNull(paths["/api/notifications/test"]!["post"]);
        Assert.NotNull(paths["/api/notifications/recent"]!["get"]);
        var view = OpenApi.Document()["components"]!["schemas"]!["NotificationSettingsView"]!["properties"]!.AsObject();
        Assert.Equal(["defaults", "mine", "effective", "sinks", "can_edit_defaults"], view.Select(kv => kv.Key));
    }
}
