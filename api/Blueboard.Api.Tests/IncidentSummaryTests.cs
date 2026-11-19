using System.Text.Json;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Xunit;

namespace Blueboard.Api.Tests;

public class IncidentSummaryTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 20, 10, 0, 0, TimeSpan.Zero);
    private static int _seq;

    private static readonly SummaryIncident Incident = new("90210", "Suspicious PowerShell on WS-042", "high", "active", JsonSerializer.SerializeToElement(new
    {
        id = "90210",
        alerts = new object[]
        {
            new
            {
                title = "Suspicious PowerShell command line",
                evidence = new object[]
                {
                    new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.deviceEvidence", ["mdeDeviceId"] = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d", ["deviceDnsName"] = "ws-042.contoso.com" },
                    new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.userEvidence", ["userAccount"] = new { userPrincipalName = "ana@contoso.com", azureAdUserId = "11111111-1111-1111-1111-111111111111" } },
                    new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.ipEvidence", ["ipAddress"] = "203.0.113.50" },
                    new Dictionary<string, object> { ["@odata.type"] = "#microsoft.graph.security.urlEvidence", ["url"] = "https://bad.example/payload.ps1" },
                },
            },
        },
    }));

    private static Message Msg(string type, string author, string body, object? payload = null, string kind = "agent", string claim = "open", int minutesAgo = 10) => new(
        Guid.NewGuid(), (++_seq).ToString(), "incidents", new Author(author, author, kind), null, Guid.Empty, "90210", type, body,
        payload is null ? null : JsonSerializer.SerializeToElement(payload), [], claim, claim == "open" ? null : author, null,
        Now.AddMinutes(-minutesAgo), 0);

    private static object Iocs(params (string Kind, string Value, string Verdict)[] list) =>
        new { indicators = list.Select(i => new { kind = i.Kind, value = i.Value, verdict = i.Verdict }).ToArray() };

    private static IncidentSummaryResult Build(params Message[] messages) => IncidentSummary.Build(Incident, messages, [], null, Now);

    [Fact]
    public void Same_ioc_from_two_reporters_is_one_row_with_both()
    {
        var s = Build(
            Msg("ioc", "agent", "iocs", Iocs(("ip", "203.0.113.50", "suspicious")), minutesAgo: 20),
            Msg("ioc", "analyst", "iocs", Iocs(("ip", "203.0.113.50", "malicious"), ("domain", "bad.example", "malicious")), kind: "human"));
        var row = Assert.Single(s.Iocs, i => i.Value == "203.0.113.50");
        Assert.Equal(["agent", "analyst"], row.Reporters);
        Assert.Equal("malicious", row.Verdict); // the strongest verdict wins
        Assert.Equal(Now.AddMinutes(-20), row.FirstSeen);
        Assert.True(row.InEvidence);
        Assert.Equal(2, s.Iocs.Count);
    }

    [Fact]
    public void Ioc_values_dedupe_ignoring_case_and_whitespace()
    {
        var s = Build(
            Msg("ioc", "agent", "x", Iocs(("domain", "Bad.Example", "unknown"))),
            Msg("ioc", "agent2", "y", Iocs(("domain", " bad.example ", "suspicious"))));
        Assert.Single(s.Iocs);
    }

    [Fact]
    public void Indicator_absent_from_evidence_and_findings_is_not_in_evidence()
    {
        var s = Build(Msg("ioc", "agent", "x", Iocs(("ip", "198.51.100.9", "malicious"), ("url", "https://bad.example/payload.ps1", "malicious"))));
        var invented = s.Iocs.Single(i => i.Value == "198.51.100.9");
        Assert.False(invented.InEvidence);
        Assert.True(invented.NotInEvidence);
        var real = s.Iocs.Single(i => i.Kind == "url");
        Assert.True(real.InEvidence);
        Assert.False(real.NotInEvidence);
    }

    [Fact]
    public void Indicator_named_in_a_finding_is_grounded_but_not_in_evidence()
    {
        var s = Build(
            Msg("finding", "agent", "Hunting shows WS-042 beaconing to 198.51.100.9 every 60 s."),
            Msg("ioc", "agent", "x", Iocs(("ip", "198.51.100.9", "malicious"))));
        var row = Assert.Single(s.Iocs);
        Assert.False(row.InEvidence);
        Assert.False(row.NotInEvidence);
    }

    [Fact]
    public void Verdict_citing_an_unknown_value_is_flagged()
    {
        var s = Build(Msg("verdict", "agent", "True positive: payload from evil.example on 203.0.113.50",
            new { classification = "truePositive", confidence = 0.9 }));
        Assert.Equal(["evil.example"], s.Verdict!.NotInEvidence);
    }

    [Fact]
    public void File_names_are_not_treated_as_domains()
    {
        Assert.DoesNotContain("update.exe", IncidentSummary.Identifiers("ran update.exe from bad.example"));
        Assert.Contains("bad.example", IncidentSummary.Identifiers("ran update.exe from bad.example"));
    }

    [Fact]
    public void Latest_verdict_wins_and_disagreement_is_noted()
    {
        var s = Build(
            Msg("verdict", "agent", "tp", new { classification = "truePositive", confidence = 0.8 }, minutesAgo: 30),
            Msg("verdict", "analyst", "fp", new { classification = "falsePositive", confidence = 0.6 }, kind: "human", minutesAgo: 5));
        Assert.Equal("falsePositive", s.Verdict!.Classification);
        Assert.Equal("analyst", s.Verdict.Author);
        Assert.True(s.VerdictsDisagree);
    }

    [Fact]
    public void One_author_changing_their_mind_is_not_disagreement()
    {
        var s = Build(
            Msg("verdict", "agent", "tp", new { classification = "unknown", confidence = 0.3 }, minutesAgo: 30),
            Msg("verdict", "agent", "tp", new { classification = "truePositive", confidence = 0.9 }, minutesAgo: 5));
        Assert.False(s.VerdictsDisagree);
        Assert.Equal(0.9, s.Verdict!.Confidence);
    }

    [Fact]
    public void Open_asks_exclude_claimed_and_checklist_questions()
    {
        var s = Build(
            Msg("question", "analyst", "Who owns WS-042?", kind: "human", minutesAgo: 90),
            Msg("question", "analyst", "Claimed one", kind: "human", claim: "claimed"),
            Msg("question", "board", "Step 1", new { checklist = new { playbook = "p", step = "a", total = 2 } }, kind: "system"));
        var ask = Assert.Single(s.OpenAsks);
        Assert.Equal(5400, ask.AgeSeconds);
    }

    [Fact]
    public void Entities_become_user_and_device_chips()
    {
        var s = Build();
        Assert.Contains(s.Entities, e => e.Kind == "user" && e.Label == "ana@contoso.com");
        Assert.Contains(s.Entities, e => e.Kind == "device" && e.Id == "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d" && e.Label == "ws-042.contoso.com");
    }

    [Fact]
    public void Actions_get_status_words()
    {
        var s = IncidentSummary.Build(Incident, [], [new SummaryActionInput(Guid.NewGuid(), "isolate_device", "pending_approval", "agent", null, Now)], null, Now);
        Assert.Equal("waiting for approval", Assert.Single(s.Actions).StatusText);
        Assert.Equal("Isolate device (MDE)", s.Actions[0].Title);
    }

    [Fact]
    public void Playbook_progress_counts_done_steps_and_hidden_ones()
    {
        var (pb, _) = Playbooks.Parse("t.md", """
            ---
            id: t
            title: Test
            match: { titles: [x] }
            steps:
              - { id: a, stage: triage, title: A }
              - { id: b, stage: triage, title: B }
              - { id: c, stage: contain, title: C, after: [a, b] }
            ---
            """);
        var s = IncidentSummary.Build(Incident, [
            Msg("question", "board", "A", new { checklist = new { playbook = "t", step = "a" } }, kind: "system", claim: "done"),
            Msg("question", "board", "B", new { checklist = new { playbook = "t", step = "b" } }, kind: "system", claim: "claimed"),
        ], [], pb, Now);
        Assert.Equal(1, s.Playbook!.Done);
        Assert.Equal(3, s.Playbook.Total);
        Assert.Equal(["done", "claimed", "hidden"], s.Playbook.Steps.Select(x => x.State));
        Assert.Contains("1 of 3 steps done", s.Markdown);
    }

    [Fact]
    public void Markdown_contains_no_raw_html_or_injected_links_from_bodies()
    {
        var s = Build(
            Msg("question", "agent", "<img src=x onerror=alert(1)> see [click](https://evil.example) **now**"),
            Msg("ioc", "agent", "x", Iocs(("url", "https://x.example/<script>", "malicious"))));
        Assert.DoesNotContain("<img", s.Markdown);
        Assert.DoesNotContain("<script", s.Markdown);
        Assert.DoesNotContain("](https://evil.example)", s.Markdown);
        Assert.Contains("&lt;img", s.Markdown);
        Assert.Contains("\\[click\\]", s.Markdown);
    }

    [Theory]
    [InlineData("a\nb", "a b")]
    [InlineData("|x|", "\\|x\\|")]
    [InlineData("<b>&", "&lt;b&gt;&amp;")]
    public void Md_escapes(string input, string expected) => Assert.Equal(expected, IncidentSummary.Md(input));

    [Fact]
    public void Ioc_payload_from_the_composer_validates()
    {
        var ok = Payloads.Validate("ioc", JsonSerializer.SerializeToElement(new { indicators = new[] { new { kind = "domain", value = "bad.example", verdict = "malicious" } } }));
        Assert.Equal("malicious", ok.GetProperty("indicators")[0].GetProperty("verdict").GetString());
        Assert.Throws<BoardException>(() => Payloads.Validate("ioc", JsonSerializer.SerializeToElement(new { indicators = new[] { new { kind = "hostname", value = "x" } } })));
    }
}
