using Blueboard.Api.Auth;
using Blueboard.Api.Core;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Audit log viewer and export, role-change auditing, inactive-principal disable. Runs as the runtime role.</summary>
public sealed class EnterpriseControlsTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private AuditLog Log => new(t.Db, t.Audit);
    private Participants Participants => new(t.Db, t.Audit, t.Board, t.System);

    [DbFact]
    public async Task Event_family_underscores_are_literal()
    {
        var admin = await t.As("analyst");
        await t.Audit.WriteAsync(admin.Id, "literal_family.child", "literal", null, Ct);
        await t.Audit.WriteAsync(admin.Id, "literalXfamily.child", "other", null, Ct);
        Assert.Single((await Log.QueryAsync(admin, new AuditQuery(Event: "literal_family."), Ct)).Rows);
        Assert.Single((await Log.QueryAsync(admin, new AuditQuery(Event: "literal_family"), Ct)).Rows);
    }

    [DbFact]
    public async Task Audit_log_filters_pages_and_is_admin_only()
    {
        var admin = await t.As("analyst");
        for (var i = 0; i < 5; i++) await t.Audit.WriteAsync(admin.Id, "test.page", $"row-{i}", new { i }, Ct);
        await t.Audit.WriteAsync(admin.Id, "test.other", "needle-subject", null, Ct);

        var page = await Log.QueryAsync(admin, new AuditQuery(Event: "test.page", Limit: 3), Ct);
        Assert.Equal(3, page.Rows.Count);
        Assert.All(page.Rows, r => Assert.Equal("test.page", r.Event));
        Assert.Equal("analyst", page.Rows[0].Actor);
        Assert.NotNull(page.Next);
        var next = await Log.QueryAsync(admin, new AuditQuery(Event: "test.page", Limit: 3, Before: page.Next), Ct);
        Assert.Equal(2, next.Rows.Count);
        Assert.True(next.Rows[0].Id < page.Rows[^1].Id);

        Assert.Equal(6, (await Log.QueryAsync(admin, new AuditQuery(Event: "test."), Ct)).Rows.Count(r => r.Event.StartsWith("test.")));
        Assert.Single((await Log.QueryAsync(admin, new AuditQuery(Subject: "NEEDLE"), Ct)).Rows);
        Assert.Contains("test.page", page.Events);

        var reader = await t.As("reader");
        Assert.Equal(403, (await Assert.ThrowsAsync<BoardException>(() => Log.QueryAsync(reader, new AuditQuery(), Ct))).Status);
    }

    [DbFact]
    public async Task Export_is_audited_formula_safe_and_people_only()
    {
        var admin = await t.As("analyst");
        await t.Audit.WriteAsync(admin.Id, "export_test.csv", "=HYPERLINK(\"http://evil\")", null, Ct);
        var csv = await Log.ExportCsvAsync(admin, new AuditQuery(Event: "export_test.csv"), Ct);
        Assert.StartsWith("id,at_utc,actor,actor_kind,event,subject,detail\n", csv);
        Assert.Contains("\"'=HYPERLINK", csv);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'audit.exported' and actor_id = @a", ("a", admin.Id)));

        var agent = await t.As("agent") with { Roles = [Roles.Poster, Roles.Admin] };
        Assert.Equal(403, (await Assert.ThrowsAsync<BoardException>(() => Log.ExportCsvAsync(agent, new AuditQuery(), Ct))).Status);
    }

    [Fact]
    public void Role_delta_lists_added_and_removed()
    {
        var (added, removed) = Authenticator.RoleDelta(["poster", "approver"], ["poster", "admin", "hunter"]);
        Assert.Equal(["admin", "hunter"], added);
        Assert.Equal(["approver"], removed);
    }

    [DbFact]
    public async Task Role_change_seen_in_a_token_is_audited_once()
    {
        var auth = new Authenticator(t.Settings, new TokenValidator(t.Settings), t.Db, t.Audit);
        var oid = Guid.NewGuid().ToString();
        CallerIdentity As(params string[] roles) => new(oid, "client", "human", "Pat Approver", "pat@contoso.com", roles);

        await auth.UpsertAsync(As(Roles.Poster), Ct);                                   // first sign-in: joined, not a change
        await auth.UpsertAsync(As(Roles.Poster), Ct);                                   // same roles: nothing
        await auth.UpsertAsync(As(Roles.Approver, Roles.Poster), Ct);                   // PIM activation / group add
        await auth.UpsertAsync(As(Roles.Approver, Roles.Poster), Ct);                   // same again: nothing
        await auth.UpsertAsync(As(Roles.Poster, Roles.Approver), Ct);                   // order is not a role change
        await auth.UpsertAsync(As(Roles.Poster), Ct);                                   // removed

        Assert.Equal(2, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.roles_changed' and subject = 'pat'"));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.roles_changed' and subject = 'pat' and detail->'added' ? 'approver'"));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.roles_changed' and subject = 'pat' and detail->'removed' ? 'approver'"));
    }

    [DbFact]
    public async Task Concurrent_role_changes_are_audited_once()
    {
        var auth = new Authenticator(t.Settings, new TokenValidator(t.Settings), t.Db, t.Audit);
        var caller = new CallerIdentity(Guid.NewGuid().ToString(), "client", "human", "Concurrent", "concurrent@contoso.com", [Roles.Poster]);
        var principal = await auth.UpsertAsync(caller, Ct);
        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => auth.UpsertAsync(caller with { Roles = [Roles.Poster, Roles.Approver] }, Ct)));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.roles_changed' and actor_id = @a", ("a", principal.Id)));
    }

    [DbFact]
    public async Task Role_change_rolls_back_if_audit_write_fails()
    {
        var auth = new Authenticator(t.Settings, new TokenValidator(t.Settings), t.Db, t.Audit);
        var caller = new CallerIdentity(Guid.NewGuid().ToString(), "client", "human", "Rollback", "rollback@contoso.com", [Roles.Poster]);
        var principal = await auth.UpsertAsync(caller, Ct);
        await t.OwnerExecAsync("""
            create function reject_role_audit() returns trigger language plpgsql as $$
            begin
              if new.event = 'principal.roles_changed' then raise exception 'test audit failure'; end if;
              return new;
            end $$;
            create trigger reject_role_audit before insert on audit_log for each row execute function reject_role_audit();
            """);
        try
        {
            await Assert.ThrowsAsync<Npgsql.PostgresException>(() => auth.UpsertAsync(caller with { Roles = [Roles.Poster, Roles.Approver] }, Ct));
            Assert.Equal(0, await t.ScalarAsync("select count(*) from principals where id = @a and 'approver' = any(roles)", ("a", principal.Id)));
        }
        finally { await t.OwnerExecAsync("drop trigger reject_role_audit on audit_log; drop function reject_role_audit()"); }
        await auth.UpsertAsync(caller with { Roles = [Roles.Poster, Roles.Approver] }, Ct);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.roles_changed' and actor_id = @a", ("a", principal.Id)));
    }

    [DbFact]
    public async Task Inactive_disable_rolls_back_if_audit_write_fails()
    {
        await using (var c = t.Db.Command("insert into principals (handle, display_name, kind, roles, last_seen_at) values ('stale-rollback', 'Stale', 'agent', '{poster}', now() - interval '120 days')"))
            await c.ExecuteNonQueryAsync(Ct);
        await t.OwnerExecAsync("""
            create function reject_disable_audit() returns trigger language plpgsql as $$
            begin
              if new.event = 'principal.disabled' then raise exception 'test audit failure'; end if;
              return new;
            end $$;
            create trigger reject_disable_audit before insert on audit_log for each row execute function reject_disable_audit();
            """);
        try
        {
            await Assert.ThrowsAsync<Npgsql.PostgresException>(() => Participants.DisableInactiveAsync(90, Ct));
            Assert.Equal(1, await t.ScalarAsync("select count(*) from principals where handle = 'stale-rollback' and enabled"));
        }
        finally
        {
            await t.OwnerExecAsync("drop trigger reject_disable_audit on audit_log; drop function reject_disable_audit()");
            await using var cleanup = t.Db.Command("update principals set last_seen_at = now() where handle = 'stale-rollback'");
            await cleanup.ExecuteNonQueryAsync(Ct);
        }
    }

    [DbFact]
    public async Task Inactive_principals_are_disabled_with_audit_and_claims_released()
    {
        await using (var c = t.Db.Command("insert into principals (handle, display_name, kind, roles, last_seen_at) values ('stale-agent', 'Stale', 'agent', '{poster}', now() - interval '120 days'), ('fresh-agent', 'Fresh', 'agent', '{poster}', now())"))
            await c.ExecuteNonQueryAsync(Ct);
        var stale = await t.As("stale-agent");
        var root = await t.Board.PostAsync(await t.As("analyst"), new PostInput("triage", "please look", "question"), ct: Ct);
        await t.OwnerExecAsync($"update messages set claim_state = 'claimed', claimed_by = '{stale.Id}', claim_expires_at = now() + interval '1 hour' where id = '{root.Id}'");

        var off = await Participants.DisableInactiveAsync(90, Ct);
        Assert.Contains("stale-agent", off);
        Assert.DoesNotContain("fresh-agent", off);
        Assert.DoesNotContain("board", off);
        Assert.Equal(0, await t.ScalarAsync("select count(*) from principals where handle = 'stale-agent' and enabled"));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.disabled' and subject = 'stale-agent' and detail->>'automatic' = 'true'"));
        Assert.Equal(0, await t.ScalarAsync("select count(*) from messages where claimed_by = @s", ("s", stale.Id)));

        Assert.Empty(await Participants.DisableInactiveAsync(90, Ct)); // idempotent
        await Assert.ThrowsAsync<BoardException>(() => Participants.DisableInactiveAsync(7, Ct));
    }
}
