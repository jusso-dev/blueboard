using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>
/// Ops/Retention.cs: old, finished records go; anything open, recent or still pointed at by unfinished work stays;
/// audit_log is never touched; a dry run removes nothing. Runs as the board's runtime role (blueboard_app).
/// </summary>
public sealed class RetentionTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private Retention Retention => new(t.Db, t.Audit, t.System, t.Settings with { RetentionDays = 90 });

    private async Task<Guid> IncidentAsync(string graphId, string status, int ageDays)
    {
        await t.Ingest.UpsertAsync(TestBoard.SampleIncident(graphId));
        var id = (await t.Board.ResolveIncidentAsync(graphId))!.Value;
        await t.OwnerExecAsync($"""
            update incidents set status = '{status}', updated_at_src = now() - interval '{ageDays} days',
              first_seen_at = now() - interval '{ageDays} days', last_synced_at = now() - interval '{ageDays} days' where id = '{id}';
            update messages set created_at = now() - interval '{ageDays} days' where incident_id = '{id}';
            """);
        return id;
    }

    private async Task<Guid> PostAsync(string channel, string body, int ageDays, Guid? parent = null, string? incident = null)
    {
        var m = await t.Board.PostAsync(await t.As("analyst"), new PostInput(channel, body, "chat", null, parent, incident), ct: Ct);
        await t.OwnerExecAsync($"update messages set created_at = now() - interval '{ageDays} days' where id = '{m.Id}'");
        return m.Id;
    }

    private async Task<Guid> ActionAsync(string status, int ageDays, Guid? incident = null, Guid? message = null)
    {
        var who = await t.As("analyst");
        var id = Guid.NewGuid();
        await t.OwnerExecAsync($"""
            insert into actions (id, kind, params, incident_id, request_message_id, requested_by, justification, status, requires_approval, created_at, updated_at)
            values ('{id}', 'run_av_scan', '{"{}"}', {(incident is { } i ? $"'{i}'" : "null")}, {(message is { } m ? $"'{m}'" : "null")},
                    '{who.Id}', 'test', '{status}', true, now() - interval '{ageDays} days', now() - interval '{ageDays} days')
            """);
        return id;
    }

    private Task<long> Exists(string table, Guid id) => t.ScalarAsync($"select count(*) from {table} where id = @id", ("id", id));

    [DbFact]
    public async Task Removes_old_finished_work_and_keeps_everything_else()
    {
        // Goes: a resolved incident untouched for 200 days, with its thread and a finished action; an old general thread.
        var oldResolved = await IncidentAsync("ret-old", "resolved", 200);
        var oldReply = await PostAsync("incidents", "old note on the incident", 200, incident: "ret-old");
        var oldAction = await ActionAsync("succeeded", 200, oldResolved);
        var oldRoot = await PostAsync("general", "old chatter", 200);
        var oldRootReply = await PostAsync("general", "old reply", 199, oldRoot);

        // Stays: an old but still active incident; a resolved incident with a recent post; a recent thread; an old
        // thread with a recent reply; an old thread an approval-pending action still points at.
        var oldActive = await IncidentAsync("ret-active", "active", 200);
        var resolvedButBusy = await IncidentAsync("ret-busy", "resolved", 200);
        await PostAsync("incidents", "fresh note", 1, incident: "ret-busy");
        var recent = await PostAsync("general", "today", 0);
        var revived = await PostAsync("general", "old question", 200);
        await PostAsync("general", "new answer", 2, revived);
        var pinned = await PostAsync("containment", "please isolate", 200);
        var pending = await ActionAsync("pending_approval", 200, null, pinned);

        await t.Audit.WriteAsync(null, "test.before-retention", "x", null, Ct);
        var auditBefore = await t.ScalarAsync("select count(*) from audit_log");

        // A dry run counts but removes nothing.
        var preview = await Retention.RunAsync(dryRun: true, ct: Ct);
        Assert.True(preview.Incidents >= 1 && preview.Messages >= 3 && preview.Actions >= 1);
        Assert.Equal(1, await Exists("incidents", oldResolved));
        Assert.Equal(auditBefore, await t.ScalarAsync("select count(*) from audit_log"));

        var r = await Retention.RunAsync(dryRun: false, ct: Ct);
        Assert.Equal(preview.Incidents, r.Incidents);

        foreach (var (table, id) in new[] { ("incidents", oldResolved), ("messages", oldReply), ("actions", oldAction), ("messages", oldRoot), ("messages", oldRootReply) })
            Assert.Equal(0, await Exists(table, id));
        foreach (var (table, id) in new[] { ("incidents", oldActive), ("incidents", resolvedButBusy), ("messages", recent), ("messages", revived), ("messages", pinned), ("actions", pending) })
            Assert.Equal(1, await Exists(table, id));

        // audit_log is only ever appended to: everything before is still there, plus one retention.purged row.
        Assert.Equal(auditBefore + 1, await t.ScalarAsync("select count(*) from audit_log"));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'retention.purged'"));

        // Nothing left to do: a second run removes nothing and writes no audit row.
        var again = await Retention.RunAsync(dryRun: false, ct: Ct);
        Assert.Equal(0, again.Total);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'retention.purged'"));
    }

    [DbFact]
    public async Task Refuses_a_period_shorter_than_thirty_days()
    {
        await Assert.ThrowsAsync<BoardException>(() => Retention.RunAsync(dryRun: true, days: 7, ct: Ct));
    }
}
