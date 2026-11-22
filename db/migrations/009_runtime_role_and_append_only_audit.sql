-- Least privilege for the board at run time, and an append-only audit_log.
--
-- blueboard_app is a NOLOGIN group role. The identity the board serves requests with (PGUSER) is made a member of it;
-- the identity that applies migrations (PG_MIGRATE_USER, the PostgreSQL Entra admin) owns the tables. The runtime role
-- can read and write board tables but can only read and insert audit_log, can't touch schema_migrations, and owns
-- nothing, so it can't change a table, drop a trigger or grant itself more. See docs/SECURITY.md.
--
-- Role names are server-wide: several databases on one server (integration tests) share the role, so creating it
-- tolerates a concurrent create. Where the migrating role can't create roles (no CREATEROLE), the grants are skipped
-- with a notice and the board keeps running as a single identity, as before.
do $$
begin
  begin
    if not exists (select 1 from pg_roles where rolname = 'blueboard_app') then
      create role blueboard_app nologin;
    end if;
  exception
    when duplicate_object or unique_violation then null;
    when insufficient_privilege then
      raise notice 'blueboard: cannot create role blueboard_app (needs CREATEROLE); runtime role separation skipped';
      return;
  end;

  execute format('grant connect on database %I to blueboard_app', current_database());
  grant usage on schema public to blueboard_app;
  grant select, insert, update, delete on all tables in schema public to blueboard_app;
  grant usage, select on all sequences in schema public to blueboard_app;
  -- Tables and sequences later migrations create are granted the same way.
  alter default privileges in schema public grant select, insert, update, delete on tables to blueboard_app;
  alter default privileges in schema public grant usage, select on sequences to blueboard_app;

  revoke update, delete, truncate on audit_log from blueboard_app;
  revoke insert, update, delete, truncate on schema_migrations from blueboard_app;
end
$$;

-- Append-only for everyone, the owner included: an UPDATE, DELETE or TRUNCATE on audit_log is refused. The owner can
-- still disable the trigger, which is itself a DDL change; the Sentinel copy (BlueboardAudit_CL) stays the
-- tamper-evident record for that case.
create or replace function audit_log_append_only() returns trigger language plpgsql as $$
begin
  raise exception 'audit_log is append-only (% refused)', tg_op using errcode = 'insufficient_privilege';
end
$$;

drop trigger if exists audit_log_no_update_delete on audit_log;
create trigger audit_log_no_update_delete before update or delete on audit_log
  for each row execute function audit_log_append_only();

drop trigger if exists audit_log_no_truncate on audit_log;
create trigger audit_log_no_truncate before truncate on audit_log
  for each statement execute function audit_log_append_only();
