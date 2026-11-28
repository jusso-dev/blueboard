using Blueboard.Api.Data;
using Npgsql;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>
/// db/migrations/009: the board's runtime role can append to audit_log but never rewrite it, can't change the schema
/// or the migration record, and even the schema owner can't update or delete audit rows.
/// </summary>
public sealed class RuntimeRoleTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task<PostgresException> RefusedAsync(string sql)
    {
        await using var c = t.Db.Command(sql);
        return await Assert.ThrowsAsync<PostgresException>(() => c.ExecuteNonQueryAsync(Ct));
    }

    [DbFact]
    public async Task Board_connects_as_the_runtime_role_not_the_owner()
    {
        await using var c = t.Db.Command("select current_user::text, pg_has_role(current_user, 'blueboard_app', 'member')");
        await using var r = await c.ExecuteReaderAsync(Ct);
        Assert.True(await r.ReadAsync(Ct));
        Assert.Equal(TestBoard.RuntimeRole, r.GetString(0));
        Assert.True(r.GetBoolean(1));
    }

    [DbFact]
    public async Task Runtime_role_appends_to_audit_log_but_cannot_rewrite_it()
    {
        await t.Audit.WriteAsync(null, "test.append", "s1", new { ok = true }, Ct);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'test.append'"));

        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("update audit_log set event = 'x' where event = 'test.append'")).SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("delete from audit_log")).SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("truncate audit_log")).SqlState);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'test.append'"));
    }

    [DbFact]
    public async Task Runtime_role_cannot_change_schema_or_migration_record()
    {
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("alter table audit_log disable trigger audit_log_no_update_delete")).SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("drop table actions")).SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("create table sneaky (id int)")).SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("delete from schema_migrations")).SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("insert into schema_migrations (name) values ('999_fake.sql')")).SqlState);
        // The setup page still reads it.
        Assert.True(await t.ScalarAsync("select count(*) from schema_migrations") >= 9);
    }

    [DbFact]
    public async Task Runtime_role_appends_agent_usage_but_cannot_rewrite_it()
    {
        var agent = await t.As("agent");
        await using (var c = t.Db.Command("insert into agent_usage (principal_id, model, input_tokens, cost_usd, cost_source) values (@p, 'm', 1, 0, 'unpriced')").With("p", agent.Id))
            await c.ExecuteNonQueryAsync(Ct);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("update agent_usage set cost_usd = 0")).SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("delete from agent_usage")).SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await RefusedAsync("truncate agent_usage")).SqlState);
        Assert.True(await t.ScalarAsync("select count(*) from agent_usage where principal_id = @p", ("p", agent.Id)) >= 1);
    }

    [DbFact]
    public async Task Even_the_owner_cannot_update_or_delete_audit_rows()
    {
        await t.Audit.WriteAsync(null, "test.owner", "s2", null, Ct);
        var ex = await Assert.ThrowsAsync<PostgresException>(() => t.OwnerExecAsync("delete from audit_log where event = 'test.owner'"));
        Assert.Contains("append-only", ex.MessageText);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'test.owner'"));
    }

    [DbFact]
    public async Task Migrating_again_is_a_no_op_and_keeps_the_grant()
    {
        Assert.Empty(await new Migrator(t.Db, t.Settings).RunAsync(Path.Combine(AppContext.BaseDirectory, "migrations"), Ct));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from pg_auth_members m join pg_roles r on r.oid = m.member join pg_roles g on g.oid = m.roleid where r.rolname = @r and g.rolname = 'blueboard_app'",
            ("r", TestBoard.RuntimeRole)));
    }
}
