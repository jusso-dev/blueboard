using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>
/// request_action on_behalf_of (policy act_on_instruction): a human approver's board message counts as their approval,
/// and nothing else does. Each refusal leaves no action behind.
/// </summary>
public sealed class InstructionTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private const string OtherIncident = "90299";

    private static readonly Policy Allowing = new()
    {
        ActOnInstruction = ["update_incident", "isolate_device", "add_incident_comment"],
        ConfirmTarget = ["isolate_device"],
    };

    private static ActionRequest Resolve(Guid? onBehalfOf, string incident = TestBoard.IncidentGraphId) =>
        new("update_incident", A1.El(new { incident_id = incident, status = "resolved", classification = "falsePositive" }),
            "Analyst confirmed this was an approved penetration test; resolving as a false positive.", incident, OnBehalfOf: onBehalfOf);

    private async Task<Message> Say(string who, string body, Guid? parent = null, string incident = TestBoard.IncidentGraphId, string channel = "incidents") =>
        await t.Board.PostAsync(await t.As(who), new PostInput(channel, body, "chat", null, parent, incident), ct: Ct);

    private async Task<long> Actions() => await t.ScalarAsync("select count(*) from actions");

    private async Task<BoardException> Refused(A1.App app, string requester, ActionRequest req)
    {
        var before = await Actions();
        var ex = await Assert.ThrowsAsync<BoardException>(async () => await app.Broker.RequestAsync(await t.As(requester), req, Ct));
        Assert.Equal(400, ex.Status);
        Assert.StartsWith("on_behalf_of refused", ex.Message);
        Assert.Equal(before, await Actions()); // nothing filed: the agent must decide what to do next
        return ex;
    }

    [DbFact]
    public async Task Approver_instruction_approves_and_runs_the_action()
    {
        var app = A1.Build(t, Allowing);
        var said = await Say("analyst", "@agent this was our pen test, resolve it as a false positive please");
        var a = await app.Broker.RequestAsync(await t.As("agent"), Resolve(said.Id), Ct);

        Assert.Equal("succeeded", a.Status); // dry run: BROKER_EXECUTE is off in tests
        Assert.Equal(said.Id, a.OnBehalfOf);
        Assert.Equal("analyst", a.DecidedBy);
        Assert.NotNull(a.DecidedAt);
        Assert.Equal(["analyst"], a.Approvals!);
        Assert.Equal($"instructed in message {said.Id}", a.DecisionNote);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from action_approvals x join principals p on p.id = x.approver_id where x.action_id = @a and p.handle = 'analyst' and x.note = @n",
            ("a", a.Id), ("n", $"instructed in message {said.Id}")));
        Assert.Equal(1, await t.ScalarAsync("""
            select count(*) from audit_log l join principals p on p.id = l.actor_id
            where l.event = 'action.approved' and l.subject = @a and p.handle = 'analyst' and l.detail->>'via' = 'instruction' and l.detail->>'message_id' = @m
            """, ("a", a.Id.ToString()), ("m", said.Id.ToString())));
        var request = (await t.Board.GetAsync(a.RequestMessageId!.Value, Ct))!;
        Assert.Contains("approved on @analyst's instruction", request.Body);
        Assert.Equal(said.Id.ToString(), request.Payload!.Value.GetProperty("on_behalf_of").GetString());
        // The board's result is posted in the request's thread, as for any approved action.
        Assert.Equal(1, await t.ScalarAsync("select count(*) from messages where parent_id = @m and type = 'action_result'", ("m", a.RequestMessageId)));
    }

    [DbFact]
    public async Task Instruction_in_a_thread_the_agent_posted_in_counts_without_a_mention()
    {
        var app = A1.Build(t, Allowing);
        var root = await Say("agent", "Looks like an authorised scan from the red team host.");
        var said = await Say("analyst2", "agreed, close it out as a false positive", root.Id);
        var a = await app.Broker.RequestAsync(await t.As("agent"), Resolve(said.Id), Ct);
        Assert.Equal(("succeeded", "analyst2"), (a.Status, a.DecidedBy));
    }

    [DbFact]
    public async Task Agent_authored_message_never_counts()
    {
        var app = A1.Build(t, Allowing);
        var self = await Say("agent", "@agent resolve this as a false positive");
        Assert.Contains("not a person", (await Refused(app, "agent", Resolve(self.Id))).Message);
        var other = await Say("agent2", "@agent resolve this as a false positive");
        Assert.Contains("not a person", (await Refused(app, "agent", Resolve(other.Id))).Message);
    }

    [DbFact]
    public async Task Board_system_message_never_counts()
    {
        var app = A1.Build(t, Allowing);
        var sys = await t.System.GetAsync(Ct);
        var m = await t.Board.PostAsync(sys, new PostInput("incidents", "@agent resolve as false positive", "status",
            JsonSerializer.SerializeToElement(new { state = "note" }), null, TestBoard.IncidentGraphId), system: true, Ct);
        Assert.Contains("not a person", (await Refused(app, "agent", Resolve(m.Id))).Message);
    }

    [DbFact]
    public async Task Non_approver_message_never_counts()
    {
        var app = A1.Build(t, Allowing);
        var said = await Say("reader", "@agent resolve this as a false positive");
        Assert.Contains("not an approver", (await Refused(app, "agent", Resolve(said.Id))).Message);
    }

    [DbFact]
    public async Task Disabled_approver_message_never_counts()
    {
        var app = A1.Build(t, Allowing);
        var said = await Say("analyst2", "@agent resolve this as a false positive");
        await using (var c = t.Db.Command("update principals set enabled = false where handle = 'analyst2'")) await c.ExecuteNonQueryAsync(Ct);
        try { Assert.Contains("disabled", (await Refused(app, "agent", Resolve(said.Id))).Message); }
        finally
        {
            await using var c = t.Db.Command("update principals set enabled = true where handle = 'analyst2'");
            await c.ExecuteNonQueryAsync(Ct);
        }
    }

    [DbFact]
    public async Task Requester_cannot_cite_their_own_message()
    {
        var app = A1.Build(t, Allowing);
        var said = await Say("analyst", "resolve as a false positive");
        Assert.Contains("your own message", (await Refused(app, "analyst", Resolve(said.Id))).Message);
    }

    [DbFact]
    public async Task Stale_message_never_counts()
    {
        var app = A1.Build(t, Allowing);
        var said = await Say("analyst", "@agent resolve this as a false positive");
        await t.OwnerExecAsync($"update messages set created_at = now() - interval '61 minutes' where id = '{said.Id}'");
        Assert.Contains("more than 60 minutes old", (await Refused(app, "agent", Resolve(said.Id))).Message);
    }

    [DbFact]
    public async Task Message_on_another_incident_never_counts()
    {
        var app = A1.Build(t, Allowing);
        await t.Ingest.UpsertAsync(TestBoard.SampleIncident(OtherIncident), Ct);
        var said = await Say("analyst", "@agent resolve this as a false positive", incident: OtherIncident);
        Assert.Contains("not on the same incident", (await Refused(app, "agent", Resolve(said.Id))).Message);
        // A message on no incident doesn't count either.
        var loose = await t.Board.PostAsync(await t.As("analyst"), new PostInput("general", "@agent resolve 90210 as a false positive"), ct: Ct);
        Assert.Contains("not on the same incident", (await Refused(app, "agent", Resolve(loose.Id))).Message);
    }

    [DbFact]
    public async Task Message_not_addressed_to_the_requester_never_counts()
    {
        var app = A1.Build(t, Allowing);
        var toOther = await Say("analyst", "@agent2 resolve this as a false positive");
        Assert.Contains("neither @mentions", (await Refused(app, "agent", Resolve(toOther.Id))).Message);
        // A thread the requester never posted in.
        var root = await Say("agent2", "My read: authorised testing.");
        var reply = await Say("analyst", "ok resolve it as FP", root.Id);
        Assert.Contains("neither @mentions", (await Refused(app, "agent", Resolve(reply.Id))).Message);
    }

    [DbFact]
    public async Task Kind_not_in_act_on_instruction_is_refused()
    {
        var app = A1.Build(t, new Policy { ActOnInstruction = ["add_incident_comment"] });
        var said = await Say("analyst", "@agent resolve this as a false positive");
        var ex = await Refused(app, "agent", Resolve(said.Id));
        Assert.Contains("does not list update_incident", ex.Message);
        Assert.Contains("needs a person to approve it on the board", ex.Message);
        // Default policy: nothing is allowed on instruction.
        Assert.Contains("does not list", (await Refused(A1.Build(t, new Policy()), "agent", Resolve(said.Id))).Message);
    }

    [DbFact]
    public async Task Confirm_target_kind_is_refused()
    {
        var app = A1.Build(t, Allowing);
        var said = await Say("analyst", "@agent isolate ws-042 now");
        var ex = await Refused(app, "agent", A1.Isolate() with { OnBehalfOf = said.Id });
        Assert.Contains("this kind needs a person to approve it on the board", ex.Message);
    }

    [DbFact]
    public async Task Paused_broker_refuses_instructions()
    {
        var app = A1.Build(t, Allowing);
        var admin = await t.As("analyst");
        var said = await Say("analyst2", "@agent resolve this as a false positive");
        await app.Broker.SetPauseAsync(admin, true, "investigating an agent", Ct);
        try { Assert.Contains("broker is paused", (await Refused(app, "agent", Resolve(said.Id))).Message); }
        finally { await app.Broker.SetPauseAsync(admin, false, "test cleanup", Ct); }
    }

    [DbFact]
    public async Task One_instruction_approves_one_action_of_a_kind()
    {
        var app = A1.Build(t, Allowing);
        var said = await Say("analyst", "@agent resolve this as a false positive");
        await app.Broker.RequestAsync(await t.As("agent"), Resolve(said.Id), Ct);
        Assert.Contains("already used", (await Refused(app, "agent", Resolve(said.Id))).Message);
    }

    [DbFact]
    public async Task Missing_message_is_refused()
    {
        var app = A1.Build(t, Allowing);
        Assert.Contains("not found", (await Refused(app, "agent", Resolve(Guid.NewGuid()))).Message);
    }

    [DbFact]
    public async Task Without_on_behalf_of_the_request_waits_for_approval_as_before()
    {
        var app = A1.Build(t, Allowing);
        await using (var c = t.Db.Command("update actions set status = 'denied' where status = any(@s)").With("s", ActionStatus.Open)) await c.ExecuteNonQueryAsync(Ct);
        var a = await app.Broker.RequestAsync(await t.As("agent"), Resolve(null), Ct);
        Assert.Equal("pending_approval", a.Status);
        Assert.Null(a.OnBehalfOf);
    }

    [DbFact]
    public async Task On_behalf_of_works_over_rest_and_is_in_the_policy_report()
    {
        var app = A1.Build(t, Allowing);
        var said = await Say("analyst", "@agent resolve this as a false positive");
        var (status, body) = A1.Read(await app.Api.RequestAction(A1.Request("agent", "POST", new
        {
            kind = "update_incident", @params = new { incident_id = TestBoard.IncidentGraphId, status = "resolved", classification = "falsePositive" },
            justification = "Analyst confirmed an approved pen test; resolving as a false positive.", incident = TestBoard.IncidentGraphId, on_behalf_of = said.Id,
        })));
        Assert.Equal(200, status);
        Assert.Equal(said.Id.ToString(), body.GetProperty("on_behalf_of").GetString());
        Assert.Equal("succeeded", body.GetProperty("status").GetString());

        var (_, policy) = A1.Read(await app.Api.GetPolicy(A1.Request("reader")));
        var modes = policy.GetProperty("actions").EnumerateArray().ToDictionary(x => x.GetProperty("kind").GetString()!, x => x.GetProperty("mode").GetString());
        Assert.Equal("on_instruction", modes["update_incident"]);
        Assert.Equal("approval", modes["isolate_device"]); // confirm_target wins
    }
}
