using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Intel;
using Blueboard.Contracts;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>WS4 on a real database: timeline and graph over stored data, add_timeline_events, and intel playbook runs (migration 018).</summary>
public sealed class AttackViewTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private AttackViews Views => new(t.Db, t.Board, t.Policy);

    [DbFact]
    public async Task Timeline_cites_alert_message_and_action_and_reported_events_stay_attributed()
    {
        var agent = await t.As("agent");
        var added = await Views.AddEventsAsync(agent, new AddTimelineEventsInput(TestBoard.IncidentGraphId,
            [new TimelineEventInput(DateTimeOffset.UtcNow.AddMinutes(-20), "ws-042.contoso.com", "powershell.exe -enc ... ran", "DeviceProcessEvents"),
             new TimelineEventInput(DateTimeOffset.UtcNow.AddMinutes(-19), "dc01.contoso.com", "logon from ws-042", "DeviceLogonEvents")],
            "Hunt: encoded PowerShell then a logon to dc01.", "DeviceProcessEvents | take 10"), Ct);
        var messageId = JsonSerializer.SerializeToElement(added, Json.Options).GetProperty("message_id").GetGuid();
        var msg = (await t.Board.GetAsync(messageId, Ct))!;
        Assert.Equal("finding", msg.Type);
        Assert.Equal("agent", msg.Author.Handle);
        Assert.NotNull(msg.ParentId); // in the incident thread

        var action = await t.Broker.RequestAsync(agent, new ActionRequest("isolate_device", JsonSerializer.SerializeToElement(new { machine_id = TestBoard.Device }),
            "Encoded PowerShell and lateral logon, see the timeline finding.", TestBoard.IncidentGraphId), Ct);

        var tl = await Views.TimelineAsync(TestBoard.IncidentGraphId, ct: Ct);
        Assert.Contains(tl.Events, e => e.Kind == "alert" && e.Refs.Any(r => r.Type == "alert"));
        var reported = tl.Events.Where(e => e.Reported).ToList();
        Assert.Equal(2, reported.Count);
        Assert.All(reported, e => Assert.Equal(["agent"], e.ReportedBy));
        Assert.True(reported.Single(e => e.Entities.Contains("ws-042.contoso.com")).InEvidence);
        Assert.False(reported.Single(e => e.Entities.Contains("dc01.contoso.com")).InEvidence);
        Assert.Contains(tl.Events, e => e.Kind == "action" && e.Refs.Any(r => r.Id == action.Id.ToString()));

        var onlyActions = await Views.TimelineAsync(TestBoard.IncidentGraphId, source: "action", ct: Ct);
        Assert.All(onlyActions.Events, e => Assert.Equal("action", e.Kind));
    }

    [DbFact]
    public async Task Participants_cannot_forge_events_with_bad_times_and_graph_hides_protected_names()
    {
        var agent = await t.As("agent");
        var future = JsonSerializer.SerializeToElement(new { events = new[] { new { ts = DateTimeOffset.UtcNow.AddDays(2).ToString("O"), entity = "x", action = "y" } } });
        await Assert.ThrowsAsync<BoardException>(() => t.Board.PostAsync(agent, new PostInput("incidents", "future", "finding", future, null, TestBoard.IncidentGraphId), ct: Ct));

        var policy = new Policy { ProtectedUsers = ["ana@contoso.com"] };
        var views = new AttackViews(t.Db, t.Board, policy);
        var asAgent = await views.GraphAsync(agent, TestBoard.IncidentGraphId, Ct);
        var ana = Assert.Single(asAgent.Nodes, n => n.Keys.Contains("ana@contoso.com"));
        Assert.True(ana.Protected);
        Assert.Null(ana.ProtectedAs);
        var asAdmin = await views.GraphAsync(await t.As("analyst"), TestBoard.IncidentGraphId, Ct);
        Assert.Equal("ana@contoso.com", asAdmin.Nodes.Single(n => n.Keys.Contains("ana@contoso.com")).ProtectedAs);
    }

    [DbFact]
    public async Task Emerging_threat_playbook_runs_from_a_ti_finding_once_and_unlocks_steps()
    {
        var analyst = await t.As("analyst");
        var intel = new IntelService(t.Db, new IntelStore(t.Db), new TiFetcher(new PgFetchCache(t.Db), t.Settings.Ti),
            new MicrosoftIntel(new Blueboard.Api.Graph.Enrichment(t.Db, t.Audit, t.Board, t.Ms), t.Ms, t.Settings),
            t.Board, new Search(t.Db, t.Board), t.System, t.Settings, NullLogger<IntelService>.Instance);
        var finding = await intel.PostFindingAsync(analyst, new TiFindingInput("GSocket used for stealthy C2", "Actors abuse GSocket relays for C2.", "high", "Vendor advisory", PostToChannel: false), Ct);

        var run = await t.Runner.StartForTiFindingAsync(analyst, finding.Id, null, Ct);
        Assert.False(run.Existing);
        Assert.Equal("emerging-threat-detection", run.PlaybookId);
        Assert.Equal(1, run.StepsPosted); // only the step without prerequisites
        Assert.NotNull(run.RootMessageId);
        var again = await t.Runner.StartForTiFindingAsync(analyst, finding.Id, null, Ct);
        Assert.True(again.Existing);
        Assert.Equal(run.Id, again.Id);

        var step = (await t.Board.GetThreadAsync(run.RootMessageId!.Value, Ct)).Replies.Single(m => PlaybookRunner.IsChecklist(m.Payload));
        Assert.Null(step.IncidentId);
        Assert.Equal(run.Id, PlaybookRunner.RunId(step.Payload));
        var agent = await t.As("agent");
        await t.Board.ClaimAsync(agent, step.Id, ct: Ct);
        await t.Runner.AfterSettleAsync(await t.Board.SettleClaimAsync(agent, step.Id, "done", Ct), Ct);
        await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => t.Runner.UnlockRunAsync(run.Id, Ct)));
        var steps = (await t.Board.GetThreadAsync(run.RootMessageId!.Value, Ct)).Replies.Where(m => PlaybookRunner.IsChecklist(m.Payload)).ToList();
        Assert.Equal(2, steps.Count); // extract-ttps-iocs, posted once despite concurrent unlocks

        // Intel playbooks never attach to incidents, and incident playbooks never run from a finding.
        await Assert.ThrowsAsync<BoardException>(() => t.Runner.AttachByIdAsync(analyst, TestBoard.IncidentGraphId, "emerging-threat-detection", Ct));
        await Assert.ThrowsAsync<BoardException>(() => t.Runner.StartForTiFindingAsync(analyst, finding.Id, "phishing", Ct));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'ti.playbook_started' and subject = @s", ("s", finding.Id.ToString())));
    }
}
