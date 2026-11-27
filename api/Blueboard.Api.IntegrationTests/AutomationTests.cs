using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Npgsql;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>
/// WS1 on a real database (db/migrations/015): the second-admin rule for loosening (in code and as SQL checks),
/// tightening applying at once, the file ceiling on overrides, the automation pause, caps, corroboration from someone
/// other than the requester, auto-revert, Keep / Revert now, and BROKER_EXECUTE=false still being a dry run.
/// </summary>
public sealed class AutomationTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly AutoRuleSpec Rule = new(0.9, ["high"], null, 2, 1, null, 60);

    /// <summary>policy.json allowing isolate_device and disable_user under a rule; isolate_device has one in the file.</summary>
    private static Policy File(AutoRuleSpec? rule = null) => new()
    {
        Automation = new AutomationPolicy
        {
            ConditionalAutoAllowed = ["isolate_device", "disable_user"],
            Rules = new() { ["isolate_device"] = rule ?? Rule },
        },
    };

    private async Task Sql(string sql, params (string, object?)[] args)
    {
        await using var c = t.Db.Command(sql);
        foreach (var (k, v) in args) c.With(k, v);
        await c.ExecuteNonQueryAsync(Ct);
    }

    /// <summary>A clean slate: no open actions, no automatic runs counted, no overrides, no pause, no verdicts.</summary>
    private async Task<(A1.App App, PolicyStore Store, Broker Broker)> Fresh(Policy file)
    {
        await Sql("update actions set status = 'denied' where status = any(@s)", ("s", ActionStatus.Open));
        await Sql("update actions set auto_rule = null, revert_state = null where auto_rule is not null or revert_state is not null");
        await Sql("delete from policy_overrides");
        await Sql("delete from playbook_triggers");
        await Sql("update policy_changes set status = 'superseded' where status = 'pending'");
        await Sql($"delete from kv_state where key = '{PolicyStore.PauseKey}'");
        await Sql("delete from messages where type = 'verdict'");
        var app = A1.Build(t, file);
        var store = new PolicyStore(app.Db, t.Audit, app.Board, t.System, file, Blueboard.Api.Board.PlaybookSet.Empty);
        var broker = new Broker(app.Db, t.Audit, app.Board, t.Ms, t.Settings, file, t.System, null, store);
        return (app, store, broker);
    }

    private async Task Verdict(string author, string classification = "truePositive", double confidence = 0.95) =>
        await t.Board.PostAsync(await t.As(author), new PostInput("incidents", "verdict", "verdict",
            JsonSerializer.SerializeToElement(new { classification, confidence }), null, TestBoard.IncidentGraphId), ct: Ct);

    private static KindOverrideInput Mode(string mode, AutoRuleSpec? rule = null, bool confirm = false, string reason = "tuning automation for the SOC") =>
        new(reason, mode, confirm, rule);

    // ── second admin ───────────────────────────────────────────────────────────────────────────

    [DbFact]
    public async Task Tightening_applies_at_once_and_is_audited()
    {
        var (_, store, _) = await Fresh(File());
        var c = await store.ChangeKindAsync(await t.As("analyst"), "isolate_device", Mode("two_approvers"), Ct);
        Assert.Equal("applied", c.Status);
        Assert.False(c.Loosening);
        Assert.Contains("isolate_device", (await store.CurrentAsync(Ct)).RequireTwoApprovers);
        Assert.Empty((await store.CurrentAsync(Ct)).ActiveRules);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'policy.change_applied' and detail->>'change_id' = @id", ("id", c.Id.ToString())));
    }

    [DbFact]
    public async Task Loosening_waits_for_a_second_different_admin()
    {
        var (_, store, _) = await Fresh(File());
        var admin1 = await t.As("analyst");
        var c = await store.ChangeKindAsync(admin1, "disable_user", Mode("approval", Rule with { RevertAfterMinutes = 30 }), Ct);
        Assert.Equal("pending", c.Status);
        Assert.True(c.Loosening);
        Assert.False((await store.CurrentAsync(Ct)).ActiveRules.ContainsKey("disable_user"));

        // The requester can't approve their own loosening.
        var self = await Assert.ThrowsAsync<BoardException>(() => store.DecideAsync(admin1, c.Id, new("approve"), Ct));
        Assert.Equal(403, self.Status);

        // A second admin (analyst2 gets admin for this test) approves it.
        await Sql("update principals set roles = array_append(roles, 'admin') where handle = 'analyst2' and not ('admin' = any(roles))");
        var decided = await store.DecideAsync(await t.As("analyst2"), c.Id, new("approve", "agreed"), Ct);
        Assert.Equal("applied", decided.Status);
        Assert.Equal("analyst2", decided.DecidedBy);
        Assert.StartsWith("disable_user@v", (await store.CurrentAsync(Ct)).ActiveRules["disable_user"].Id);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'policy.change_approved' and detail->>'change_id' = @id", ("id", c.Id.ToString())));
    }

    [DbFact]
    public async Task Sql_refuses_a_loosening_applied_by_its_requester()
    {
        var (_, store, _) = await Fresh(File());
        var admin = await t.As("analyst");
        var c = await store.ChangeKindAsync(admin, "disable_user", Mode("approval", Rule with { RevertAfterMinutes = 30 }), Ct);
        // Bypass the service: the CHECK constraint still refuses it.
        var ex = await Assert.ThrowsAsync<PostgresException>(() => Sql(
            "update policy_changes set status = 'applied', decided_by = requested_by, decided_at = now() where id = @id", ("id", c.Id)));
        Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
    }

    [DbFact]
    public async Task Expired_changes_cannot_be_approved()
    {
        var (_, store, _) = await Fresh(File());
        var c = await store.ChangeKindAsync(await t.As("analyst"), "disable_user", Mode("approval", Rule with { RevertAfterMinutes = 30 }), Ct);
        await Sql("update policy_changes set expires_at = now() - interval '1 second' where id = @id", ("id", c.Id));
        // SQL trigger: even a direct update can't apply an expired change.
        await Assert.ThrowsAsync<PostgresException>(() => Sql(
            "update policy_changes set status = 'applied', decided_by = (select id from principals where handle = 'analyst2'), decided_at = now() where id = @id", ("id", c.Id)));
        Assert.True(await store.ExpireChangesAsync(Ct) >= 1);
        Assert.Equal("expired", (await store.GetChangeAsync(c.Id, Ct))!.Status);
    }

    [DbFact]
    public async Task Overrides_cannot_exceed_the_file_ceiling()
    {
        var (_, store, _) = await Fresh(File());
        var admin = await t.As("analyst");
        await Assert.ThrowsAsync<BoardException>(() => store.ChangeKindAsync(admin, "revoke_sessions", Mode("approval", Rule with { RevertAfterMinutes = null }), Ct));
        await Assert.ThrowsAsync<BoardException>(() => store.ChangeKindAsync(admin, "isolate_device", Mode("auto"), Ct));
        await Assert.ThrowsAsync<BoardException>(() => store.ChangeKindAsync(admin, "isolate_device", Mode("approval", Rule with { MaxPerHour = 500 }), Ct));
        // A row written behind the store's back that exceeds the ceiling is ignored when the policy is read.
        await Sql("""insert into policy_overrides (kind, setting, updated_by) values ('revoke_sessions', '{"mode":"auto","confirm_target":false,"rule":null}', (select id from principals where handle = 'analyst'))""");
        store.Invalidate();
        var p = await store.CurrentAsync(Ct);
        Assert.DoesNotContain("revoke_sessions", p.AutoApprove);
    }

    [DbFact]
    public async Task Agents_and_non_admins_cannot_change_policy()
    {
        var (_, store, _) = await Fresh(File());
        // Even an agent row that somehow carries the admin role is refused: only people administer policy.
        var agent = await t.As("agent") with { Roles = ["poster", "admin"] };
        Assert.Equal(403, (await Assert.ThrowsAsync<BoardException>(() => store.ChangeKindAsync(agent, "isolate_device", Mode("two_approvers"), Ct))).Status);
        Assert.Equal(403, (await Assert.ThrowsAsync<BoardException>(() => store.SetPauseAsync(agent, new(true, "agent wants a pause"), Ct))).Status);
        var reader = await t.As("reader");
        Assert.Equal(403, (await Assert.ThrowsAsync<BoardException>(() => store.ChangeKindAsync(reader, "isolate_device", Mode("two_approvers"), Ct))).Status);
    }

    // ── kill switch ────────────────────────────────────────────────────────────────────────────

    [DbFact]
    public async Task Pause_applies_at_once_and_resume_needs_a_second_admin()
    {
        var (_, store, broker) = await Fresh(File());
        await Verdict("analyst");
        await store.SetPauseAsync(await t.As("analyst"), new(true, "reviewing automation"), Ct);
        var a = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        Assert.Equal("pending_approval", a.Status);
        Assert.Contains(a.PolicyNotes, n => n.Contains("automation is paused"));

        var resume = (PolicyChange)await store.SetPauseAsync(await t.As("analyst"), new(false, "review finished"), Ct);
        Assert.Equal("pending", resume.Status);
        Assert.True((await store.PauseAsync(Ct)).Paused);
    }

    // ── conditional auto, caps, corroboration ──────────────────────────────────────────────────

    [DbFact]
    public async Task Corroborated_request_auto_executes_as_a_dry_run_and_schedules_a_revert()
    {
        Assert.False(t.Settings.BrokerExecute);
        var (_, _, broker) = await Fresh(File());
        await Verdict("analyst");
        var a = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        Assert.Equal("succeeded", a.Status);
        Assert.Equal("isolate_device@file", a.AutoRule);
        Assert.Null(a.DecidedBy);
        Assert.True(a.Result!.Value.GetProperty("dry_run").GetBoolean()); // BROKER_EXECUTE=false: nothing reached Defender
        Assert.Equal("scheduled", a.RevertState);
        Assert.Equal(60, a.RevertAfterMinutes);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'action.auto_approved' and subject = @id", ("id", a.Id.ToString())));
    }

    [DbFact]
    public async Task Requesters_own_verdict_does_not_corroborate()
    {
        var (_, _, broker) = await Fresh(File());
        await Verdict("agent", confidence: 1.0);
        var a = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        Assert.Equal("pending_approval", a.Status);
        Assert.Null(a.AutoRule);
    }

    [DbFact]
    public async Task Per_incident_cap_falls_back_to_approval()
    {
        var (_, _, broker) = await Fresh(File());
        await Verdict("analyst");
        var first = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        Assert.Equal("isolate_device@file", first.AutoRule);
        var second = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        Assert.Equal("pending_approval", second.Status);
        Assert.Contains(second.PolicyNotes, n => n.Contains("cap reached"));
    }

    [DbFact]
    public async Task Concurrent_requests_cannot_both_slip_under_the_cap()
    {
        var (_, _, broker) = await Fresh(File(Rule with { MaxPerIncident = 1, MaxPerHour = 1 }));
        await Verdict("analyst");
        var agent = await t.As("agent");
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => broker.RequestAsync(agent, A1.Isolate(), Ct)));
        Assert.Equal(1, results.Count(r => r.AutoRule is not null));
    }

    [DbFact]
    public async Task Protected_device_is_rejected_even_with_a_rule()
    {
        var file = File() with { ProtectedDevices = ["ws-042"] };
        var (_, _, broker) = await Fresh(file);
        await Verdict("analyst");
        Assert.Equal("rejected", (await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct)).Status);
    }

    // ── playbook triggers ──────────────────────────────────────────────────────────────────────

    [DbFact]
    public async Task Trigger_rules_disable_at_once_and_new_triggers_need_a_second_admin()
    {
        await Fresh(File());
        var books = t.Playbooks;
        var store = new PolicyStore(t.Db, t.Audit, t.Board, t.System, File(), books);
        var incident = TestBoard.SampleIncident();
        var before = await store.MatchPlaybookAsync(incident, Ct);
        Assert.NotNull(before); // the sample PowerShell incident matches a file playbook

        // Disabling the matching file trigger is tightening: no playbook attaches.
        var off = await store.ChangeTriggerAsync(await t.As("analyst"), PolicyStore.FileTriggerId(before!),
            new TriggerInput("too noisy for this tenant", Titles: ["PowerShell"], Enabled: false), Ct);
        Assert.Equal("applied", off.Status);
        store.Invalidate();
        var now = await store.MatchPlaybookAsync(incident, Ct);
        Assert.NotEqual(before, now);

        // Adding a custom trigger is loosening: pending until a second admin approves it.
        var add = await store.ChangeTriggerAsync(await t.As("analyst"), "ps-high",
            new TriggerInput("route PowerShell incidents to endpoint", before, 900, ["high"], Titles: ["PowerShell"]), Ct);
        Assert.Equal("pending", add.Status);
        Assert.True(add.Loosening);
        await Sql("update principals set roles = array_append(roles, 'admin') where handle = 'analyst2' and not ('admin' = any(roles))");
        await store.DecideAsync(await t.As("analyst2"), add.Id, new("approve"), Ct);
        store.Invalidate();
        Assert.Equal(before, await store.MatchPlaybookAsync(incident, Ct));
    }

    // ── revert ─────────────────────────────────────────────────────────────────────────────────

    [DbFact]
    public async Task Due_revert_files_the_reverse_action_as_the_board_and_runs_it()
    {
        var (_, _, broker) = await Fresh(File());
        await Verdict("analyst");
        var a = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        await Sql("update actions set revert_at = now() - interval '1 second' where id = @id", ("id", a.Id));
        Assert.True(await broker.RevertDueAsync(Ct) >= 1);
        var after = (await broker.GetAsync(a.Id, Ct))!;
        Assert.Equal("reverted", after.RevertState);
        var rev = (await broker.GetAsync(after.RevertActionId!.Value, Ct))!;
        Assert.Equal("release_device", rev.Kind);
        Assert.Equal("board", rev.RequestedBy);
        Assert.Equal(a.Id, rev.RevertOf);
        Assert.Equal("succeeded", rev.Status);
        Assert.Equal(0, await broker.RevertDueAsync(Ct)); // exactly once
    }

    [DbFact]
    public async Task Keep_cancels_the_revert_and_agents_cannot()
    {
        var (_, _, broker) = await Fresh(File());
        await Verdict("analyst");
        var a = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        Assert.Equal(403, (await Assert.ThrowsAsync<BoardException>(() => broker.RevertOpAsync(t.As("agent").Result, a.Id, new("keep"), Ct))).Status);
        var kept = await broker.RevertOpAsync(await t.As("analyst"), a.Id, new("keep", "still active"), Ct);
        Assert.Equal("kept", kept.RevertState);
        await Sql("update actions set revert_at = now() - interval '1 second' where id = @id", ("id", a.Id));
        await broker.RevertDueAsync(Ct);
        Assert.Null((await broker.GetAsync(a.Id, Ct))!.RevertActionId);
    }

    [DbFact]
    public async Task Revert_now_runs_the_reverse_action_approved_by_that_person()
    {
        var (_, _, broker) = await Fresh(File());
        await Verdict("analyst");
        var a = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        var after = await broker.RevertOpAsync(await t.As("analyst2"), a.Id, new("now"), Ct);
        Assert.Equal("reverted", after.RevertState);
        var rev = (await broker.GetAsync(after.RevertActionId!.Value, Ct))!;
        Assert.Contains("analyst2", rev.Approvals!);
    }

    [DbFact]
    public async Task Revert_is_policy_rechecked_and_a_rejection_is_reported()
    {
        var (_, _, broker) = await Fresh(File());
        await Verdict("analyst");
        var a = await broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        // release_device disabled after the isolation ran: the revert can't run and the requester hears about it.
        var tightened = File() with { Disabled = ["release_device"] };
        var store2 = new PolicyStore(t.Db, t.Audit, t.Board, t.System, tightened, Blueboard.Api.Board.PlaybookSet.Empty);
        var broker2 = new Broker(t.Db, t.Audit, t.Board, t.Ms, t.Settings, tightened, t.System, null, store2);
        await Sql("update actions set revert_at = now() - interval '1 second' where id = @id", ("id", a.Id));
        await broker2.RevertDueAsync(Ct);
        Assert.Equal("failed", (await broker2.GetAsync(a.Id, Ct))!.RevertState);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'action.revert_failed' and subject = @id", ("id", a.Id.ToString())));
    }

    [DbFact]
    public async Task Revert_after_minutes_is_refused_for_irreversible_kinds()
    {
        var (_, _, broker) = await Fresh(File());
        var req = new ActionRequest("revoke_sessions", A1.El(new { user = "ana@contoso.com" }), "Token theft from ana's session on ws-042; revoke sessions.",
            TestBoard.IncidentGraphId, RevertAfterMinutes: 30);
        Assert.Contains("has no automatic revert", (await Assert.ThrowsAsync<BoardException>(() => broker.RequestAsync(t.As("agent").Result, req, Ct))).Message);
    }
}
