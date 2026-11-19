using System.Diagnostics;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

public sealed class QueueAndPlaybookTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static JsonElement Incident(string id, string title, string severity = "medium", string status = "active", string? category = null, params string[] techniques) =>
        JsonSerializer.SerializeToElement(new Dictionary<string, object>
        {
            ["id"] = id, ["displayName"] = title, ["severity"] = severity, ["status"] = status,
            ["createdDateTime"] = DateTimeOffset.UtcNow.AddHours(-2), ["lastUpdateDateTime"] = DateTimeOffset.UtcNow,
            ["alerts"] = new object[] { new Dictionary<string, object?> { ["id"] = $"a{id}", ["title"] = title, ["category"] = category, ["mitreTechniques"] = techniques } },
        });

    private async Task<List<Message>> StepsAsync(Guid incidentId) =>
        (await t.Board.ListForIncidentAsync(incidentId, Ct)).Where(m => PlaybookRunner.IsChecklist(m.Payload)).ToList();

    private static string Step(Message m) => m.Payload!.Value.GetProperty("checklist").GetProperty("step").GetString()!;

    [DbFact]
    public async Task Phishing_incident_gets_the_phishing_playbook_and_steps_unlock_in_order()
    {
        await t.Ingest.UpsertAsync(Incident("70001", "Email messages containing malicious URL removed after delivery", category: "InitialAccess", techniques: "T1566.002"), Ct);
        var id = (await t.Board.ResolveIncidentAsync("70001", Ct))!.Value;
        Assert.Equal("phishing", (await t.Incidents.SummaryAsync(id, Ct)).Playbook!.Id);

        // Only steps without prerequisites are visible at first, posted as replies to the incident's root message.
        var steps = await StepsAsync(id);
        Assert.Equal(["scope-recipients", "analyse-payload"], steps.Select(Step));
        Assert.All(steps, s => Assert.NotNull(s.ParentId));

        // Claim and complete with the ordinary claim functions; dependants appear only when every prerequisite is done.
        var agent = await t.As("agent");
        var scope = steps.Single(s => Step(s) == "scope-recipients");
        await t.Board.ClaimAsync(agent, scope.Id, ct: Ct);
        await t.Runner.UnlockAsync(id, Ct);
        Assert.Equal(2, (await StepsAsync(id)).Count); // claimed is not done
        var done = await t.Board.SettleClaimAsync(agent, scope.Id, "done", Ct);
        await t.Runner.AfterSettleAsync(done, Ct);
        Assert.Contains("check-clicks", (await StepsAsync(id)).Select(Step));
        Assert.DoesNotContain("purge", (await StepsAsync(id)).Select(Step)); // still waits on analyse-payload

        var payload = steps.Single(s => Step(s) == "analyse-payload");
        await t.Board.ClaimAsync(agent, payload.Id, ct: Ct);
        await t.Runner.AfterSettleAsync(await t.Board.SettleClaimAsync(agent, payload.Id, "done", Ct), Ct);
        var now = (await StepsAsync(id)).Select(Step).ToList();
        Assert.Contains("purge", now);
        Assert.Contains("block-indicators", now);
        Assert.Equal(now.Count, now.Distinct().Count());

        var summary = await t.Incidents.SummaryAsync(id, Ct);
        Assert.Equal(2, summary.Playbook!.Done);
        Assert.Equal(7, summary.Playbook.Total);
        Assert.Empty(summary.OpenAsks); // checklist steps show as progress, not as open asks

        // Playbooks never run or request actions.
        Assert.Equal(0, await t.ScalarAsync("select count(*) from actions where incident_id = @i", ("i", id)));
    }

    [DbFact]
    public async Task Unlock_is_idempotent_and_reingest_does_not_reattach()
    {
        await t.Ingest.UpsertAsync(Incident("70002", "Impossible travel activity", "high"), Ct);
        var id = (await t.Board.ResolveIncidentAsync("70002", Ct))!.Value;
        var before = (await StepsAsync(id)).Count;
        await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => t.Runner.UnlockAsync(id, Ct)));
        await t.Runner.UnlockPendingAsync(Ct);
        await t.Ingest.UpsertAsync(Incident("70002", "Impossible travel activity", "medium"), Ct);
        Assert.Equal(before, (await StepsAsync(id)).Count);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from incident_playbooks where incident_id = @i", ("i", id)));
    }

    [DbFact]
    public async Task Unmatched_incident_gets_no_playbook()
    {
        await t.Ingest.UpsertAsync(Incident("70003", "Unusual discovery commands", category: "Discovery"), Ct);
        var id = (await t.Board.ResolveIncidentAsync("70003", Ct))!.Value;
        Assert.Null((await t.Incidents.SummaryAsync(id, Ct)).Playbook);
    }

    [DbFact]
    public async Task Summary_merges_iocs_from_two_reporters_and_flags_invented_ones()
    {
        var agent = await t.As("agent");
        var analyst = await t.As("analyst");
        JsonElement Ioc(string kind, string value, string verdict) =>
            JsonSerializer.SerializeToElement(new { indicators = new[] { new { kind, value, verdict } } });
        await t.Board.PostAsync(agent, new PostInput("intel", "ip", "ioc", Ioc("ip", "203.0.113.50", "suspicious"), null, TestBoard.IncidentGraphId), ct: Ct);
        await t.Board.PostAsync(analyst, new PostInput("intel", "ip", "ioc", Ioc("ip", "203.0.113.50", "malicious"), null, TestBoard.IncidentGraphId), ct: Ct);
        await t.Board.PostAsync(agent, new PostInput("intel", "made up", "ioc", Ioc("domain", "nowhere.example", "malicious"), null, TestBoard.IncidentGraphId), ct: Ct);
        var s = await t.Incidents.SummaryAsync(t.IncidentId, Ct);
        var ip = Assert.Single(s.Iocs, i => i.Value == "203.0.113.50");
        Assert.Equal(["agent", "analyst"], ip.Reporters);
        Assert.True(ip.InEvidence);
        Assert.True(s.Iocs.Single(i => i.Value == "nowhere.example").NotInEvidence);
    }

    [DbFact]
    public async Task Queue_puts_needs_a_human_first_and_handles_200_incidents_quickly()
    {
        // 200 incidents, each with a handful of messages, plus a few with pending approvals and human asks.
        await using (var cmd = t.Db.Command("""
            insert into incidents (graph_id, display_name, severity, status, alert_count, data, updated_at_src)
            select 'q' || g, 'Seeded incident ' || g, (array['low','medium','high','informational'])[1 + g % 4],
                   case when g % 10 = 0 then 'resolved' else 'active' end, 1, '{}'::jsonb, now() - make_interval(mins => g)
            from generate_series(1, 200) g
            """))
            await cmd.ExecuteNonQueryAsync(Ct);
        await using (var cmd = t.Db.Command("""
            insert into messages (channel_id, author_id, incident_id, type, body, payload, mentions)
            select (select id from channels where name = 'triage'), (select id from principals where handle = 'agent'), i.id,
                   (array['chat','finding','question','verdict','ioc'])[1 + k % 5], 'seed ' || k,
                   case when k % 5 = 3 then '{"classification":"truePositive","confidence":0.8}'::jsonb end,
                   case when k % 5 = 2 and i.graph_id in ('q7', 'q8') then array['analyst'] else '{}' end
            from incidents i cross join generate_series(0, 9) k where i.graph_id like 'q%'
            """))
            await cmd.ExecuteNonQueryAsync(Ct);
        var agent = await t.As("agent");
        var pending = await t.Broker.RequestAsync(agent, new ActionRequest("isolate_device",
            JsonSerializer.SerializeToElement(new { machine_id = TestBoard.Device }), "Queue ordering test: isolate the device from the sample.", "q151"), Ct);
        Assert.Equal("pending_approval", pending.Status);

        var me = await t.As("analyst");
        await t.Incidents.QueueAsync(me, ct: Ct); // warm up
        var sw = Stopwatch.StartNew();
        var rows = await t.Incidents.QueueAsync(me, ct: Ct);
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 500, $"queue took {sw.ElapsedMilliseconds} ms");

        Assert.DoesNotContain(rows, r => r.Status == "resolved");
        Assert.Equal("q151", rows[0].GraphId); // pending approval first (q150 is resolved, so not in the queue)
        Assert.Equal(1, rows[0].PendingActions);
        Assert.True(rows[0].NeedsHuman);
        Assert.Equal(["q7", "q8"], rows.Skip(1).Take(2).Select(r => r.GraphId).Order()); // then asks that mention a person
        Assert.All(rows.Skip(1).Take(2), r => Assert.Equal(2, r.HumanAsks));
        var q9 = rows.Single(r => r.GraphId == "q9");
        Assert.Equal("truePositive", q9.Verdict);
        Assert.Equal(2, q9.OpenAsks);
        Assert.True(rows.Single(r => r.GraphId == "q7").Mine); // mentions @analyst
        Assert.False(q9.Mine);

        // After the needs-a-human block, severity then last activity.
        var rest = rows.Where(r => !r.NeedsHuman).Select(r => r.Severity switch { "high" => 3, "medium" => 2, "low" => 1, _ => 0 }).ToList();
        Assert.Equal(rest.OrderByDescending(x => x).ToList(), rest);

        var all = await t.Incidents.QueueAsync(me, includeResolved: true, Ct);
        Assert.Contains(all, r => r.Status == "resolved");
    }
}
