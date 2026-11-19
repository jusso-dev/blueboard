using Blueboard.Contracts;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Issue #9: expiry, policy re-check at approval time, the two-person rule and typed confirmation.</summary>
public sealed class ApprovalTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task Sql(string sql, params (string, object?)[] args)
    {
        await using var c = t.Db.Command(sql);
        foreach (var (k, v) in args) c.With(k, v);
        await c.ExecuteNonQueryAsync(Ct);
    }

    /// <summary>Each test starts with an empty approval queue so the per-incident cap never interferes.</summary>
    private async Task<A1.App> Fresh(Policy policy)
    {
        await Sql("update actions set status = 'denied' where status = any(@s)", ("s", ActionStatus.Open));
        return A1.Build(t, policy);
    }

    [DbFact]
    public async Task New_requests_expire_after_four_hours_by_default_and_per_kind_overrides_apply()
    {
        var app = await Fresh(new Policy { ExpiryHoursByKind = new() { ["disable_user"] = 1 } });
        var iso = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        var dis = await app.Broker.RequestAsync(await t.As("agent"), A1.Disable(), Ct);
        Assert.InRange((iso.ExpiresAt!.Value - iso.CreatedAt).TotalHours, 3.99, 4.01);
        Assert.InRange((dis.ExpiresAt!.Value - dis.CreatedAt).TotalHours, 0.99, 1.01);
    }

    [DbFact]
    public async Task Expired_request_cannot_be_approved()
    {
        var app = await Fresh(new Policy());
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        await Sql("update actions set expires_at = now() - interval '1 second' where id = @id", ("id", a.Id));

        var ex = await Assert.ThrowsAsync<BoardException>(() => app.Broker.DecideAsync(t.As("analyst").Result, a.Id, "approve", null, Ct));
        Assert.Equal(409, ex.Status);
        Assert.Equal("action is expired", ex.Message);
        Assert.Equal("expired", (await app.Broker.GetAsync(a.Id, Ct))!.Status);
    }

    [DbFact]
    public async Task Expired_approval_returns_409_over_rest()
    {
        var app = await Fresh(new Policy());
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        await Sql("update actions set expires_at = now() - interval '1 second' where id = @id", ("id", a.Id));
        var (status, body) = A1.Read(await app.Api.Decide(A1.Request("analyst", "POST", new { decision = "approve" }), a.Id.ToString()));
        Assert.Equal(409, status);
        Assert.Equal("action is expired", body.GetProperty("error").GetString());
    }

    [DbFact]
    public async Task Expiry_sweep_marks_expired_posts_a_status_and_audits()
    {
        var app = await Fresh(new Policy());
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        await Sql("update actions set expires_at = now() - interval '1 minute' where id = @id", ("id", a.Id));

        Assert.True(await app.Broker.ExpireDueAsync(Ct) >= 1);
        Assert.Equal("expired", (await app.Broker.GetAsync(a.Id, Ct))!.Status);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'action.expired' and subject = @id", ("id", a.Id.ToString())));
        // The status reply is in the request's thread and @mentions the requester, so they hear about it.
        Assert.Equal(1, await t.ScalarAsync("""
            select count(*) from messages where parent_id = @m and type = 'status' and payload->>'state' = 'action_expired' and 'agent' = any(mentions)
            """, ("m", a.RequestMessageId)));
        Assert.Equal(0, await app.Broker.ExpireDueAsync(Ct)); // nothing left to expire: the sweep is idempotent
    }

    [DbFact]
    public async Task Approval_is_refused_when_the_device_became_protected_after_the_request()
    {
        var before = await Fresh(new Policy());
        var a = await before.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        Assert.Equal("pending_approval", a.Status);

        // An admin adds the device (by host name) to protected_devices and the board reloads policy.
        var after = A1.Build(t, new Policy { ProtectedDevices = ["ws-042"] });
        var ex = await Assert.ThrowsAsync<BoardException>(() => after.Broker.DecideAsync(t.As("analyst").Result, a.Id, "approve", null, Ct));
        Assert.Equal(409, ex.Status);
        Assert.Contains("is a protected device", ex.Message);
        var row = (await after.Broker.GetAsync(a.Id, Ct))!;
        Assert.Equal("rejected", row.Status);
        Assert.Contains(row.PolicyNotes, n => n.StartsWith("rejected when re-checked at approval"));
        Assert.Equal(0, await t.ScalarAsync("select count(*) from messages where type = 'action_result' and payload->>'action_id' = @id", ("id", a.Id.ToString())));
    }

    [DbFact]
    public async Task Denial_still_works_after_policy_would_reject()
    {
        var before = await Fresh(new Policy());
        var a = await before.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        var after = A1.Build(t, new Policy { ProtectedDevices = ["ws-042"] });
        Assert.Equal("denied", (await after.Broker.DecideAsync(await t.As("analyst"), a.Id, "deny", "no", Ct)).Status);
    }

    [DbFact]
    public async Task Two_approver_kind_needs_two_different_people()
    {
        var app = await Fresh(new Policy { RequireTwoApprovers = ["disable_user"] });
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Disable(), Ct);
        Assert.Equal(2, a.ApprovalsRequired);

        var first = await app.Broker.DecideAsync(await t.As("analyst"), a.Id, "approve", "looks right", Ct);
        Assert.Equal("approved_once", first.Status);
        Assert.Equal(["analyst"], first.Approvals!);
        Assert.Equal(0, await t.ScalarAsync("select count(*) from messages where type = 'action_result' and payload->>'action_id' = @id", ("id", a.Id.ToString())));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'action.approved_once' and subject = @id", ("id", a.Id.ToString())));

        var again = await Assert.ThrowsAsync<BoardException>(() => app.Broker.DecideAsync(t.As("analyst").Result, a.Id, "approve", null, Ct));
        Assert.Equal(409, again.Status);
        Assert.Contains("different approver", again.Message);

        var done = await app.Broker.DecideAsync(await t.As("analyst2"), a.Id, "approve", null, Ct);
        Assert.Equal("succeeded", done.Status);
        Assert.Equal(["analyst", "analyst2"], done.Approvals!);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from messages where type = 'action_result' and payload->>'action_id' = @id", ("id", a.Id.ToString())));
    }

    [DbFact]
    public async Task Concurrent_first_approvals_by_two_people_still_count_to_two()
    {
        var app = await Fresh(new Policy { RequireTwoApprovers = ["disable_user"] });
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Disable(), Ct);
        var (p1, p2) = (await t.As("analyst"), await t.As("analyst2"));
        await Task.WhenAll(app.Broker.DecideAsync(p1, a.Id, "approve", null, Ct), app.Broker.DecideAsync(p2, a.Id, "approve", null, Ct));
        Assert.Equal("succeeded", (await app.Broker.GetAsync(a.Id, Ct))!.Status);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from messages where type = 'action_result' and payload->>'action_id' = @id", ("id", a.Id.ToString())));
    }

    [DbFact]
    public async Task One_of_two_approval_can_still_be_denied_and_can_expire()
    {
        var app = await Fresh(new Policy { RequireTwoApprovers = ["disable_user"] });
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Disable(), Ct);
        await app.Broker.DecideAsync(await t.As("analyst"), a.Id, "approve", null, Ct);
        await Sql("update actions set expires_at = now() - interval '1 second' where id = @id", ("id", a.Id));
        await app.Broker.ExpireDueAsync(Ct);
        Assert.Equal("expired", (await app.Broker.GetAsync(a.Id, Ct))!.Status);

        var b = await app.Broker.RequestAsync(await t.As("agent"), A1.Disable(), Ct);
        await app.Broker.DecideAsync(await t.As("analyst"), b.Id, "approve", null, Ct);
        Assert.Equal("denied", (await app.Broker.DecideAsync(await t.As("analyst2"), b.Id, "deny", "not this one", Ct)).Status);
    }

    [DbFact]
    public async Task Requester_cannot_be_either_approver()
    {
        var app = await Fresh(new Policy { RequireTwoApprovers = ["disable_user"] });
        var a = await app.Broker.RequestAsync(await t.As("analyst"), A1.Disable(), Ct);
        await app.Broker.DecideAsync(await t.As("analyst2"), a.Id, "approve", null, Ct);
        var ex = await Assert.ThrowsAsync<BoardException>(() => app.Broker.DecideAsync(t.As("analyst").Result, a.Id, "approve", null, Ct));
        Assert.Equal(403, ex.Status);
        Assert.Equal("approved_once", (await app.Broker.GetAsync(a.Id, Ct))!.Status);
    }

    [DbFact]
    public async Task Confirm_target_is_enforced_server_side()
    {
        var app = await Fresh(new Policy { ConfirmTarget = ["isolate_device"] });
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        var listed = (await app.Broker.ListAsync("open", Ct)).Single(x => x.Id == a.Id);
        Assert.Equal("ws-042.contoso.com", listed.ConfirmPrompt);

        var none = await Assert.ThrowsAsync<BoardException>(() => app.Broker.DecideAsync(t.As("analyst").Result, a.Id, "approve", null, Ct));
        Assert.Contains("type the target (ws-042.contoso.com)", none.Message);
        await Assert.ThrowsAsync<BoardException>(() => app.Broker.DecideAsync(t.As("analyst").Result, a.Id, "approve", null, Ct, confirm: "ws-043"));
        Assert.Equal("pending_approval", (await app.Broker.GetAsync(a.Id, Ct))!.Status);

        // Any name for the same device works, case-insensitively. Denying never needs the confirmation.
        Assert.Equal("succeeded", (await app.Broker.DecideAsync(await t.As("analyst"), a.Id, "approve", null, Ct, confirm: " WS-042 ")).Status);
        var b = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        Assert.Equal("denied", (await app.Broker.DecideAsync(await t.As("analyst"), b.Id, "deny", null, Ct)).Status);
    }

    [DbFact]
    public async Task Confirm_over_rest_is_read_from_the_body()
    {
        var app = await Fresh(new Policy { ConfirmTarget = ["isolate_device"] });
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        var (bad, _) = A1.Read(await app.Api.Decide(A1.Request("analyst", "POST", new { decision = "approve" }), a.Id.ToString()));
        Assert.Equal(400, bad);
        var (ok, body) = A1.Read(await app.Api.Decide(A1.Request("analyst", "POST", new { decision = "approve", confirm = "ws-042.contoso.com" }), a.Id.ToString()));
        Assert.Equal(200, ok);
        Assert.Equal("succeeded", body.GetProperty("status").GetString());
    }

    [DbFact]
    public async Task Reports_count_new_statuses_and_the_dry_run_section()
    {
        var app = await Fresh(new Policy { RequireTwoApprovers = ["disable_user"] });
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Disable(), Ct);
        await app.Broker.DecideAsync(await t.As("analyst"), a.Id, "approve", null, Ct);
        var b = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        await Sql("update actions set expires_at = now() - interval '1 second' where id = @id", ("id", b.Id));
        await app.Broker.ExpireDueAsync(Ct);
        var c = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        await app.Broker.DecideAsync(await t.As("analyst"), c.Id, "approve", null, Ct);

        var r = await t.Reporting.BuildAsync(null, null, null, Ct);
        Assert.Contains(r.Actions, o => o.Status == "approved_once" && o.N >= 1);
        Assert.Contains(r.Actions, o => o.Status == "expired" && o.N >= 1);
        var iso = r.DryRun!.Kinds.Single(k => k.Kind == "isolate_device");
        Assert.True(iso.RanApproved >= 1);
        Assert.True(iso.Expired >= 1);
        Assert.True(r.DryRun.WouldHaveRun >= 1);
    }
}
