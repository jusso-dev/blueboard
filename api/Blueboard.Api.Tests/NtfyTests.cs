using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Ops;
using Blueboard.Api.Webhooks;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>The ntfy sink: the JSON publish body, priority and tags, caps and escaping, and the URL guard.</summary>
public class NtfyTests
{
    private static Notifier N(Settings s) =>
        new(new HttpClient(), new Db(new Settings { DatabaseUrl = "postgres://u:p@127.0.0.1:1/none" }), null!, null!, s);

    private static MessageNotice Msg(string evt, string? classification = null, string? severity = "high", NoticeAction? action = null, string? summary = "Credential theft on ws-042") =>
        new(evt, Guid.Parse("11111111-2222-3333-4444-555555555555"), "triage", new Author("enrichment-agent", "Enrichment agent", "agent"), evt,
            summary, "90210", "Suspicious PowerShell", severity, classification, classification is null ? null : 0.92, action,
            [new NotificationRecipient("ana", "Ana Lopez", "ana@contoso.com")], "https://board.example/channels/triage#m-11111111-2222-3333-4444-555555555555");

    private static Notice Approval(string evt) =>
        new(evt, Guid.NewGuid(), "Isolate device (MDE)", "ws-042", "agent", "90210", "Suspicious PowerShell", "high", 1, "https://board.example/approvals#x", "pending_approval");

    // ── body shape ───────────────────────────────────────────────────────────────────────────────
    [Fact]
    public void Json_body_has_the_ntfy_publish_shape()
    {
        var json = JsonNode.Parse(Notifier.NtfyJson(Notifier.Ntfy(Msg("question")), "blueboard"))!.AsObject();
        Assert.Equal(["topic", "title", "message", "priority", "tags", "click"], json.Select(kv => kv.Key));
        Assert.Equal("blueboard", json["topic"]!.GetValue<string>());
        Assert.Equal("@enrichment-agent needs your input", json["title"]!.GetValue<string>());
        Assert.Equal(4, json["priority"]!.GetValue<int>());
        Assert.Equal(["question"], json["tags"]!.AsArray().Select(t => t!.GetValue<string>()));
        Assert.Equal("https://board.example/channels/triage#m-11111111-2222-3333-4444-555555555555", json["click"]!.GetValue<string>());
        Assert.False(json.ContainsKey("markdown")); // agent text is untrusted: never rendered as Markdown
        Assert.False(json.ContainsKey("actions"));
        var lines = json["message"]!.GetValue<string>().Split('\n');
        Assert.Equal("From: @enrichment-agent (Enrichment agent)", lines[0]);
        Assert.Contains("Channel: #triage", lines);
        Assert.Contains("Incident: 90210 (high): Suspicious PowerShell", lines);
        Assert.Contains("Summary: Credential theft on ws-042", lines);
        Assert.Contains("For: @ana", lines);
    }

    [Fact]
    public void Click_is_left_out_without_a_link()
    {
        var json = JsonNode.Parse(Notifier.NtfyJson(Notifier.Ntfy(Msg("mention") with { Url = null }), "t"))!.AsObject();
        Assert.False(json.ContainsKey("click"));
    }

    [Fact]
    public void Approval_notices_never_carry_the_justification()
    {
        var body = Notifier.NtfyJson(Notifier.Ntfy(Approval("action.pending_approval")), "t");
        Assert.DoesNotContain("justification", body, StringComparison.OrdinalIgnoreCase);
        var message = JsonNode.Parse(body)!["message"]!.GetValue<string>();
        Assert.StartsWith("Action: Isolate device (MDE)\nTarget: ws-042\nRequested by: @agent", message);
    }

    // ── priority and tags ────────────────────────────────────────────────────────────────────────
    [Theory]
    [InlineData("question", null, "high", 4, "question")]
    [InlineData("mention", null, "high", 4, "speech_balloon")]
    [InlineData("reply", null, "high", 3, null)]
    [InlineData("verdict", "truePositive", "low", 5, "rotating_light")]
    [InlineData("verdict", "unknown", "high", 3, "mag")]
    [InlineData("verdict", "falsePositive", "high", 3, "mag")]
    [InlineData("finding", null, "high", 4, "mag")]
    [InlineData("finding", null, "medium", 3, "mag")]
    [InlineData("incident", null, "high", 4, "warning")]
    [InlineData("incident", null, "low", 3, "warning")]
    [InlineData("incident", null, null, 3, "warning")]
    public void Message_events_map_to_priority_and_tags(string evt, string? classification, string? severity, int priority, string? tag)
    {
        var n = Notifier.Ntfy(Msg(evt, classification, severity));
        Assert.Equal(priority, n.Priority);
        Assert.Equal(tag is null ? [] : [tag], n.Tags);
    }

    [Theory]
    [InlineData("succeeded", 3, "white_check_mark")]
    [InlineData("failed", 5, "x")]
    public void Action_results_map_to_priority_and_tags(string status, int priority, string tag)
    {
        var n = Notifier.Ntfy(Msg("action_result", action: new NoticeAction(Guid.NewGuid(), "Update incident", status)));
        Assert.Equal(priority, n.Priority);
        Assert.Equal([tag], n.Tags);
    }

    [Theory]
    [InlineData("action.pending_approval", 4, "lock")]
    [InlineData("action.second_approval_needed", 4, "lock")]
    [InlineData("action.reminder", 4, "lock")]
    [InlineData("action.failed", 5, "x")]
    [InlineData("action.interrupted", 5, "x")]
    [InlineData("action.expired", 3, "lock")]
    public void Approval_events_map_to_priority_and_tags(string evt, int priority, string tag)
    {
        var n = Notifier.Ntfy(Approval(evt));
        Assert.Equal(priority, n.Priority);
        Assert.Equal([tag], n.Tags);
    }

    [Fact]
    public void Test_notice_is_default_priority()
    {
        var n = Notifier.Ntfy(new Notice("test", null, "Test notification", "No action", "ana", null, null, null, 0, null, "test"));
        Assert.Equal(3, n.Priority);
        Assert.Empty(n.Tags);
        Assert.Equal("Test notification", n.Title);
        Assert.Null(n.Click);
    }

    // ── caps and escaping ────────────────────────────────────────────────────────────────────────
    [Fact]
    public void Title_and_message_are_plain_and_capped()
    {
        var hostile = "evil‮gnp.exe\r\nInjected: line\u0000 [x](https://evil.example) **bold**";
        var n = Notifier.Ntfy(Msg("finding", summary: hostile + new string('a', 2000)) with { Author = new Author(new string('h', 400), "D\nisplay", "agent") });
        Assert.True(n.Title.Length <= Notifier.NtfyTitleMax);
        Assert.True(n.Message.Length <= Notifier.NtfyMessageMax);
        Assert.EndsWith("…", n.Message);
        Assert.DoesNotContain('‮', n.Message);
        Assert.DoesNotContain('\r', n.Message);
        Assert.DoesNotContain('\0', n.Message);
        Assert.DoesNotContain('\n', n.Title);
        // Every line is "Key: value": a value can't start a line of its own.
        Assert.All(n.Message.Split('\n'), l => Assert.Matches(@"^(From|Channel|Incident|Summary|For): ", l));
        Assert.DoesNotContain("\nInjected", n.Message);

        // JSON-encoded, so quotes and backslashes can't break out of the body.
        var body = Notifier.NtfyJson(Notifier.Ntfy(Msg("question", summary: "\"},\"click\":\"https://evil.example\",\"x\":\"\\")), "t");
        var json = JsonNode.Parse(body)!.AsObject();
        Assert.Equal("https://board.example/channels/triage#m-11111111-2222-3333-4444-555555555555", json["click"]!.GetValue<string>());
        Assert.Contains("Summary: \"},\"click\":\"https://evil.example\",\"x\":\"\\", json["message"]!.GetValue<string>());
    }

    [Fact]
    public void Long_message_is_cut_on_a_character_boundary()
    {
        var emoji = string.Concat(Enumerable.Repeat("😀", 400));
        var n = Notifier.Ntfy(Msg("question", summary: emoji));
        Assert.True(n.Message.Length <= Notifier.NtfyMessageMax);
        for (var i = 0; i < n.Message.Length; i++)
            if (char.IsHighSurrogate(n.Message[i])) Assert.True(i + 1 < n.Message.Length && char.IsLowSurrogate(n.Message[i + 1]));
        JsonDocument.Parse(Notifier.NtfyJson(n, "t")); // still valid UTF-16 → JSON
    }

    // ── URL guard ────────────────────────────────────────────────────────────────────────────────
    private static readonly Settings Hosts = new() { NotifyAllowedHosts = ["ntfy", "ntfy.example.com", "hooks.example.com"] };

    [Theory]
    [InlineData("http://ntfy/blueboard")]
    [InlineData("http://ntfy:8080/blueboard")]
    [InlineData("https://ntfy:8443/blueboard")]
    [InlineData("https://ntfy.example.com/blueboard")]
    [InlineData("https://NTFY.example.com/soc_alerts-1/")]
    public void Ntfy_urls_that_are_allowed(string url) => Assert.Null(N(Hosts).NtfyProblem(url));

    [Theory]
    [InlineData("http://ntfy.example.com/blueboard", "https")]          // dotted host: https only
    [InlineData("https://ntfy.example.com:8443/blueboard", "custom port")] // dotted host: default port only
    [InlineData("http://other/blueboard", "NOTIFY_ALLOWED_HOSTS")]      // single-label but not allowed
    [InlineData("http://ntfy.evil.example/blueboard", "https")]
    [InlineData("https://evil.example/blueboard", "NOTIFY_ALLOWED_HOSTS")]
    [InlineData("http://user:pw@ntfy/blueboard", "credentials")]
    [InlineData("http://10.0.0.5:8080/blueboard", "https")]              // IP literals never get the http exception
    [InlineData("https://10.0.0.5/blueboard", "IP address")]
    [InlineData("http://[::1]:8080/blueboard", "https")]
    [InlineData("ftp://ntfy/blueboard", "https")]
    [InlineData("https://ntfy.example.com/", "one topic")]
    [InlineData("https://ntfy.example.com/a/b", "one topic")]
    [InlineData("https://ntfy.example.com/bad.topic", "one topic")]
    [InlineData("https://ntfy.example.com/blueboard?auth=x", "query")]
    public void Ntfy_urls_that_are_refused(string url, string problem)
    {
        var p = N(Hosts).NtfyProblem(url);
        Assert.NotNull(p);
        Assert.Contains(problem, p);
        Assert.DoesNotContain("evil.example/blueboard", p); // the URL itself isn't echoed
    }

    [Theory]
    [InlineData("http://ntfy/x")]
    [InlineData("https://ntfy:8443/x")]
    public void Other_sinks_keep_the_strict_guard_even_for_single_label_hosts(string url) =>
        Assert.NotNull(N(Hosts).UrlProblem(url, "NOTIFY_WEBHOOK_URL"));

    [Fact]
    public void Only_the_single_label_ntfy_host_may_resolve_privately()
    {
        var s = Hosts with { NotifyNtfyUrl = "http://ntfy:8080/blueboard" };
        Assert.True(Notifier.MayBePrivate(s, "ntfy"));
        Assert.True(Notifier.MayBePrivate(s, "NTFY"));
        Assert.False(Notifier.MayBePrivate(s, "hooks.example.com"));
        Assert.False(Notifier.MayBePrivate(s, "other"));
        Assert.False(Notifier.MayBePrivate(s with { NotifyAllowedHosts = ["hooks.example.com"] }, "ntfy"));
        Assert.False(Notifier.MayBePrivate(s with { NotifyNtfyUrl = "https://ntfy.example.com/blueboard" }, "ntfy.example.com"));
        Assert.False(Notifier.MayBePrivate(s with { NotifyNtfyUrl = null }, "ntfy"));
    }

    [Theory]
    [InlineData("10.0.0.5", true)]
    [InlineData("172.18.0.3", true)]
    [InlineData("192.168.1.10", true)]
    [InlineData("fd00::5", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.169.254", false)] // cloud metadata stays refused
    [InlineData("100.64.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("fe80::1", false)]
    public void Private_network_means_rfc1918_and_unique_local_only(string ip, bool expected) =>
        Assert.Equal(expected, OutboundGuard.IsPrivateNetwork(IPAddress.Parse(ip)));

    // ── sink state ───────────────────────────────────────────────────────────────────────────────
    [Theory]
    [InlineData(null, null)]
    [InlineData("tk_faketoken0000000000000000000", null)]
    [InlineData("hunter2", "NOTIFY_NTFY_TOKEN must be an ntfy access token")]
    [InlineData("tk_bad token", "NOTIFY_NTFY_TOKEN must be an ntfy access token")]
    public void Ntfy_sink_state(string? token, string? problem)
    {
        var sink = N(Hosts with { NotifyNtfyUrl = "http://ntfy/blueboard", NotifyNtfyToken = token }).Sinks().Single();
        Assert.Equal("ntfy", sink.Sink);
        if (problem is null) Assert.Null(sink.Problem); else Assert.StartsWith(problem, sink.Problem);
        if (token is not null) Assert.DoesNotContain(token, sink.Problem ?? "");
    }

    [Fact]
    public void Ntfy_sink_reports_a_bad_url_without_echoing_it()
    {
        var sink = N(Hosts with { NotifyNtfyUrl = "http://ntfy.example.com/blueboard" }).Sinks().Single();
        Assert.Contains("NOTIFY_NTFY_URL must be an https URL", sink.Problem);
        Assert.DoesNotContain("ntfy.example.com", sink.Problem);
        Assert.Empty(N(Hosts).Sinks()); // not configured: not listed
    }

    // ── settings document ────────────────────────────────────────────────────────────────────────
    [Fact]
    public void Ntfy_is_a_sink_setting_that_defaults_on()
    {
        Assert.Contains("ntfy", NotificationRules.SinkKeys);
        Assert.True(NotificationRules.BuiltIn.Sinks.Ntfy);
        Assert.True(NotificationRules.SinkOn(NotificationRules.BuiltIn, "ntfy"));
        var off = NotificationRules.Effective(NotificationRules.BuiltIn, NotificationRules.ValidatePatch(JsonDocument.Parse("""{"sinks":{"ntfy":false}}""").RootElement));
        Assert.False(NotificationRules.SinkOn(off, "ntfy"));
        Assert.True(off.Sinks.Webhook);
        Assert.Equal(["webhook", "teams", "mail", "ntfy"], JsonNode.Parse(Json.Serialize(NotificationRules.BuiltIn))!["sinks"]!.AsObject().Select(kv => kv.Key));
    }

    [Fact]
    public void Stored_documents_from_before_ntfy_still_parse()
    {
        // A full defaults document saved before ntfy existed: sinks has only the three older keys.
        var old = JsonNode.Parse(Json.Serialize(NotificationRules.BuiltIn))!.AsObject();
        old["sinks"]!.AsObject().Remove("ntfy");
        old["sinks"]!["mail"] = false;
        var stored = NotificationRules.ValidatePatch(JsonDocument.Parse(old.ToJsonString()).RootElement, allowNull: false);
        var s = NotificationRules.Overlay(NotificationRules.BuiltIn, stored);
        Assert.True(s.Sinks.Ntfy);
        Assert.False(s.Sinks.Mail);

        // The contract itself: a sinks object without ntfy deserialises with the default.
        var direct = JsonSerializer.Deserialize<NotificationSinkToggles>("""{"webhook":true,"teams":false,"mail":true}""", Json.Options)!;
        Assert.True(direct.Ntfy);
        Assert.False(direct.Teams);
    }
}
