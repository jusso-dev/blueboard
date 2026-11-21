using System.Text.Json;
using Blueboard.Api.Board;
using Xunit;

namespace Blueboard.Api.Tests;

public class PlaybookTests
{
    private static string Doc(string steps, string match = "match: { titles: [phish] }") => $"""
        ---
        id: test
        title: Test playbook
        {match}
        steps:
        {steps}
        ---

        Notes for people.
        """;

    private const string Good = """
          - { id: a, stage: triage, title: First }
          - { id: b, stage: investigate, title: Second, after: [a] }
          - { id: c, stage: contain, title: Third, after: [a, b], suggested_action: isolate_device }
        """;

    private static Playbook Parse(string text)
    {
        var (pb, error) = Playbooks.Parse("test.md", text);
        Assert.True(pb is not null, error);
        return pb!;
    }

    private static string Error(string text)
    {
        var (pb, error) = Playbooks.Parse("test.md", text);
        Assert.Null(pb);
        return error!;
    }

    [Fact]
    public void Parses_front_matter_and_notes()
    {
        var pb = Parse(Doc(Good));
        Assert.Equal("test", pb.Id);
        Assert.Equal(3, pb.Steps.Count);
        Assert.Equal(["a", "b"], pb.Steps[2].After);
        Assert.Equal("isolate_device", pb.Steps[2].SuggestedAction);
        Assert.Equal("Notes for people.", pb.Notes);
    }

    [Theory]
    [InlineData("  - { id: a, stage: triage, title: A, after: [zz] }", "unknown step 'zz'")]
    [InlineData("  - { id: a, stage: triage, title: A, after: [b] }\n  - { id: b, stage: triage, title: B, after: [a] }", "cycle")]
    [InlineData("  - { id: a, stage: pray, title: A }", "stage must be one of")]
    [InlineData("  - { id: a, stage: triage, title: A, suggested_action: format_disk }", "unknown suggested_action")]
    [InlineData("  - { id: a, stage: triage, title: A }\n  - { id: a, stage: triage, title: B }", "duplicate step id")]
    [InlineData("  - { id: a, stage: triage, title: A, sugested_action: run_av_scan }", "invalid front matter")]
    [InlineData("  - { id: A_1, stage: triage, title: A }", "lower-case slug")]
    public void Rejects_bad_steps(string steps, string expected) => Assert.Contains(expected, Error(Doc(steps)));

    [Fact]
    public void Rejects_missing_front_matter_and_empty_match()
    {
        Assert.Contains("front matter", Error("# Just markdown"));
        Assert.Contains("match needs", Error(Doc(Good, "match: {}")));
        Assert.Contains("invalid MITRE", Error(Doc(Good, "match: { techniques: [Phishing] }")));
    }

    [Fact]
    public void Load_skips_bad_files_and_reports_them()
    {
        var dir = Directory.CreateTempSubdirectory("bbpb").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "a-good.md"), Doc(Good));
            File.WriteAllText(Path.Combine(dir, "b-bad.md"), "no front matter");
            File.WriteAllText(Path.Combine(dir, "c-dupe.md"), Doc(Good));
            var set = Playbooks.Load(dir);
            Assert.Single(set.All);
            Assert.Equal(["b-bad.md", "c-dupe.md"], set.Problems.Select(p => p.File));
            Assert.Contains("duplicate playbook id", set.Problems[1].Error);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Bundled_starter_playbooks_are_valid()
    {
        var set = Playbooks.Load(Path.Combine(AppContext.BaseDirectory, "playbooks"));
        Assert.Empty(set.Problems);
        Assert.Equal(
        [
            "azure-privilege-escalation",
            "bec-aitm-token-theft",
            "data-exfiltration-cloud",
            "endpoint-powershell",
            "malware-infostealer",
            "oauth-app-consent-abuse",
            "password-spray-mfa-fatigue",
            "phishing",
            "ransomware-lateral-movement",
            "risky-sign-in",
        ], set.All.Select(p => p.Id));
        Assert.All(set.All, p => Assert.InRange(p.Steps.Count, 6, 10));
    }

    private static JsonElement Incident(string title, string? category = null, params string[] techniques) => JsonSerializer.SerializeToElement(new
    {
        displayName = "Incident",
        severity = "high",
        alerts = new[] { new { title, category, mitreTechniques = techniques, serviceSource = "microsoftDefenderForEndpoint" } },
    });

    [Fact]
    public void Matches_service_sources_severities_and_priority()
    {
        var m = new PlaybookMatch([], [], [], ["microsoftDefenderForCloud"], ["high"]);
        var cloudHigh = JsonSerializer.SerializeToElement(new { displayName = "X", severity = "high", alerts = new[] { new { title = "A", serviceSource = "microsoftDefenderForCloud" } } });
        var cloudLow = JsonSerializer.SerializeToElement(new { displayName = "X", severity = "low", alerts = new[] { new { title = "A", serviceSource = "microsoftDefenderForCloud" } } });
        Assert.True(Playbooks.Matches(m, cloudHigh));
        Assert.False(Playbooks.Matches(m, cloudLow));

        var set = Playbooks.Load(Path.Combine(AppContext.BaseDirectory, "playbooks"));
        // Higher-priority ransomware playbook wins over generic PowerShell when LSASS credential theft is also present.
        Assert.Equal("ransomware-lateral-movement", set.Match(Incident("PowerShell + LSASS credential dump", "Execution", "T1059.001", "T1003.001"))?.Id);
        Assert.Equal("bec-aitm-token-theft", set.Match(Incident("Suspicious inbox forwarding rule", "Persistence", "T1564.008"))?.Id);
        Assert.Equal("oauth-app-consent-abuse", set.Match(Incident("Illicit OAuth consent grant", "CredentialAccess", "T1528"))?.Id);
        Assert.Equal("azure-privilege-escalation", set.Match(cloudHigh)?.Id);
    }

    [Fact]
    public void Matches_titles_categories_and_techniques()
    {
        var m = new PlaybookMatch(["Execution"], ["phish"], ["T1566"]);
        Assert.True(Playbooks.Matches(m, Incident("A potentially malicious URL click was detected / PHISHING")));
        Assert.True(Playbooks.Matches(m, Incident("Something", "execution")));
        Assert.True(Playbooks.Matches(m, Incident("Something", null, "T1566.002")));
        Assert.False(Playbooks.Matches(m, Incident("Something", null, "T15660")));
        Assert.False(Playbooks.Matches(m, Incident("Impossible travel", "InitialAccess", "T1078")));
    }

    [Fact]
    public void First_match_in_file_order_wins()
    {
        var set = Playbooks.Load(Path.Combine(AppContext.BaseDirectory, "playbooks"));
        Assert.Equal("phishing", set.Match(Incident("Email messages containing malicious URL removed after delivery", "InitialAccess", "T1566.002"))?.Id);
        Assert.Equal("endpoint-powershell", set.Match(Incident("Suspicious PowerShell download cradle", null, "T1059.001"))?.Id);
        Assert.Equal("risky-sign-in", set.Match(Incident("Impossible travel activity", "InitialAccess"))?.Id);
        Assert.Null(set.Match(Incident("Unrelated alert", "Discovery")));
    }

    [Fact]
    public void Steps_unlock_only_when_every_prerequisite_is_done()
    {
        var pb = Parse(Doc(Good));
        Assert.Equal(["a"], PlaybookRunner.Unlocked(pb, new Dictionary<string, string>()).Select(s => s.Id));
        Assert.Empty(PlaybookRunner.Unlocked(pb, new Dictionary<string, string> { ["a"] = "claimed" }));
        Assert.Equal(["b"], PlaybookRunner.Unlocked(pb, new Dictionary<string, string> { ["a"] = "done" }).Select(s => s.Id));
        Assert.Empty(PlaybookRunner.Unlocked(pb, new Dictionary<string, string> { ["a"] = "done", ["b"] = "open" }));
        Assert.Equal(["c"], PlaybookRunner.Unlocked(pb, new Dictionary<string, string> { ["a"] = "done", ["b"] = "done" }).Select(s => s.Id));
    }

    [Fact]
    public void Step_post_is_a_checklist_question_and_never_an_action()
    {
        var pb = Parse(Doc(Good));
        var post = PlaybookRunner.StepPost(pb, pb.Steps[2], Guid.NewGuid(), Guid.NewGuid());
        Assert.Equal("question", post.Type);
        var c = post.Payload!.Value.GetProperty("checklist");
        Assert.Equal("c", c.GetProperty("step").GetString());
        Assert.Equal(3, c.GetProperty("n").GetInt32());
        Assert.Equal("isolate_device", c.GetProperty("suggested_action").GetString());
        Assert.Contains("doesn't run it", post.Body);
    }
}
