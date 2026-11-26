using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Http;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>Emoji reactions, and the rules for acting on a person's instruction (policy act_on_instruction).</summary>
public class ReactionsAndInstructionTests
{
    [Theory]
    [InlineData("👍")]
    [InlineData("👀")]
    [InlineData("✅")]
    [InlineData("❤️")]          // heart + variation selector
    [InlineData("👍🏽")]          // skin tone
    [InlineData("👩‍💻")]          // ZWJ sequence
    [InlineData("👨‍👩‍👧‍👦")]       // longer ZWJ sequence
    [InlineData("🏳️‍🌈")]          // flag ZWJ sequence
    [InlineData("🇦🇺")]          // regional indicator flag
    [InlineData("1️⃣")]          // keycap
    [InlineData("🏴󠁧󠁢󠁳󠁣󠁴󠁿")]          // subdivision flag (tag characters)
    [InlineData("☕")]
    [InlineData("↔️")]
    public void Emoji_accepts_one_emoji(string emoji) => Assert.Null(Emoji.Check(emoji));

    [Theory]
    [InlineData("", "required")]
    [InlineData("a", "not text")]
    [InlineData("7", "not text")]
    [InlineData("+", "not text")]
    [InlineData(":", "not text")]
    [InlineData(" ", "not text")]
    [InlineData("é", "not text")]
    [InlineData("日", "not text")]
    [InlineData("👍👍", "single emoji")]
    [InlineData("👍a", "single emoji")]
    [InlineData(":+1:", "single emoji")]
    [InlineData("‍", "not text")]
    public void Emoji_refuses_text_and_more_than_one(string emoji, string why) =>
        Assert.Contains(why, Emoji.Check(emoji));

    [Fact]
    public void Emoji_refuses_more_than_32_characters() =>
        Assert.Contains("at most 32", Emoji.Check(new string('️', 33)));

    [Fact]
    public void Emoji_validate_throws_a_400()
    {
        var ex = Assert.Throws<BoardException>(() => Emoji.Validate("lol"));
        Assert.Equal(400, ex.Status);
        Assert.Equal("👍", Emoji.Validate(" 👍 "));
    }

    [Fact]
    public void Message_json_has_reactions_in_snake_case()
    {
        var m = new Message(Guid.NewGuid(), "1", "general", new Author("a", "A", "human"), null, null, null, "chat", "hi", null, [], "open", null, null,
            DateTimeOffset.UtcNow, 0, Reactions: [new Reaction("👍", 2, ["a", "b"])]);
        var json = JsonDocument.Parse(Json.Serialize(m)).RootElement;
        var r = json.GetProperty("reactions")[0];
        Assert.Equal("👍", r.GetProperty("emoji").GetString());
        Assert.Equal(2, r.GetProperty("count").GetInt32());
        Assert.Equal(["a", "b"], r.GetProperty("handles").EnumerateArray().Select(x => x.GetString()));
    }

    [Fact]
    public void Openapi_lists_reaction_and_typing_routes_and_tools()
    {
        var doc = OpenApi.Document();
        var paths = doc["paths"]!.AsObject();
        Assert.True(paths.ContainsKey("/api/messages/{id}/reactions"));
        Assert.NotNull(paths["/api/typing"]!["get"]);
        Assert.NotNull(paths["/api/typing"]!["post"]);
        var tools = doc["x-mcp-tools"]!.AsObject();
        Assert.True(tools.ContainsKey("react"));
        Assert.True(tools.ContainsKey("set_typing"));
        Assert.NotNull(Contract.SchemaFor<ActionRequest>()["properties"]!["on_behalf_of"]);
    }

    // ── policy ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Act_on_instruction_parses_and_defaults_to_none()
    {
        Assert.Empty(new Policy().ActOnInstruction);
        var p = Policy.Parse("""{ "act_on_instruction": ["update_incident", "add_incident_comment"] }""");
        Assert.Equal(["update_incident", "add_incident_comment"], p.ActOnInstruction);
        Assert.Equal("on_instruction", PolicyReport.ModeOf("update_incident", p));
        Assert.Contains("counts as the approval", PolicyReport.Build(p).Actions.Single(a => a.Kind == "update_incident").Words);
    }

    [Fact]
    public void Act_on_instruction_with_an_unknown_kind_fails() =>
        Assert.Contains("act_on_instruction: unknown action kind resolve_incident",
            Assert.Throws<PolicyException>(() => Policy.Parse("""{ "act_on_instruction": ["resolve_incident"] }""")).Message);

    [Fact]
    public void Act_on_instruction_overlapping_two_approvers_fails() =>
        Assert.Contains("act_on_instruction: disable_user is in require_two_approvers",
            Assert.Throws<PolicyException>(() => Policy.Parse("""{ "act_on_instruction": ["disable_user"], "require_two_approvers": ["disable_user"] }""")).Message);

    [Fact]
    public void Confirm_target_kind_in_act_on_instruction_is_warned_and_shown_as_approval()
    {
        var p = Policy.Parse("""{ "act_on_instruction": ["isolate_device"], "confirm_target": ["isolate_device"] }""");
        Assert.Equal("approval", PolicyReport.ModeOf("isolate_device", p));
        Assert.Contains(PolicyReport.WarningsFor(p), w => w.StartsWith("isolate_device is in both act_on_instruction and confirm_target"));
    }

    // ── instruction rules ─────────────────────────────────────────────────────────────────────

    private static readonly Principal Agent = new(Guid.NewGuid(), "enrichment-agent", "Enrichment agent", "agent", ["poster", "requester"]);
    private static readonly Guid Incident = Guid.NewGuid();
    private static readonly Guid Msg = Guid.NewGuid();
    private static readonly Policy OnInstruction = new() { ActOnInstruction = ["update_incident", "isolate_device"], ConfirmTarget = ["isolate_device"] };

    private static Instruction Good() => new(Msg, Guid.NewGuid(), "analyst", "human", true, ["poster", "approver"], Incident,
        TimeSpan.FromMinutes(2), MentionsRequester: true, RequesterInThread: false, AlreadyUsed: false);

    [Fact]
    public void Instruction_from_an_approver_on_the_same_incident_counts()
    {
        Assert.Null(InstructionRules.CheckPolicy("update_incident", OnInstruction, paused: false, approvalsRequired: 1));
        Assert.Null(InstructionRules.CheckMessage(Good(), Msg, Agent, Incident));
        Assert.Null(InstructionRules.CheckMessage(Good() with { MentionsRequester = false, RequesterInThread = true }, Msg, Agent, Incident));
    }

    [Theory]
    [InlineData("run_av_scan", false, 1, "does not list run_av_scan")]
    [InlineData("isolate_device", false, 1, "needs a person to approve it on the board")]
    [InlineData("update_incident", false, 2, "needs two approvers")]
    [InlineData("update_incident", true, 1, "broker is paused")]
    public void Policy_rules_refuse(string kind, bool paused, int approvals, string expected) =>
        Assert.Contains(expected, InstructionRules.CheckPolicy(kind, OnInstruction, paused, approvals));

    public static TheoryData<string, string> Refusals => new()
    {
        { "agent", "not a person" },
        { "system", "not a person" },
        { "disabled", "is disabled" },
        { "not_approver", "not an approver" },
        { "self", "your own message" },
        { "other_incident", "not on the same incident" },
        { "no_incident", "must be linked to the incident" },
        { "stale", "more than 60 minutes old" },
        { "not_addressed", "neither @mentions" },
        { "reused", "already used" },
        { "missing", "not found" },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public void Message_rules_refuse(string variant, string expected)
    {
        var g = Good();
        var actionIncident = (Guid?)Incident;
        Instruction? m = variant switch
        {
            "agent" => g with { AuthorKind = "agent" },
            "system" => g with { AuthorKind = "system" },
            "disabled" => g with { AuthorEnabled = false },
            "not_approver" => g with { AuthorRoles = ["poster", "requester"] },
            "self" => g with { AuthorId = Agent.Id },
            "other_incident" => g with { IncidentId = Guid.NewGuid() },
            "stale" => g with { Age = TimeSpan.FromMinutes(61) },
            "not_addressed" => g with { MentionsRequester = false, RequesterInThread = false },
            "reused" => g with { AlreadyUsed = true },
            "missing" => null,
            _ => g,
        };
        if (variant == "no_incident") actionIncident = null;
        Assert.Contains(expected, InstructionRules.CheckMessage(m, Msg, Agent, actionIncident));
    }

    [Fact]
    public void A_message_with_no_incident_never_matches_an_action_on_one() =>
        Assert.Contains("not on the same incident", InstructionRules.CheckMessage(Good() with { IncidentId = null }, Msg, Agent, Incident));
}
