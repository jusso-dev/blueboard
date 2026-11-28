-- Review fixes for 015-019 (which may already be applied, so they are left as they are).

-- Budget notices go out once per agent and period, however often a block is cleared and re-applied in it
-- (Agents/AgentBudgets.cs, under a per-principal advisory lock). Rows blocked before this migration were notified.
alter table agent_budget_state add column if not exists notified_at timestamptz;
update agent_budget_state set notified_at = exceeded_at where notified_at is null and exceeded_at is not null;

-- Okta secondEmail is user-editable, so it is no longer an identity link (TM-55). Drop the values already stored;
-- the column stays for older builds and is always null from now on.
update identity_links set second_email = null where second_email is not null;

-- Lookups and ON DELETE SET NULL / CASCADE from messages scan these columns: index them.
create index if not exists agent_usage_message on agent_usage (message_id) where message_id is not null;
create index if not exists agent_usage_claim_message on agent_usage (claim_message_id) where claim_message_id is not null;
create index if not exists agent_feedback_message on agent_feedback (message_id);

-- agent_usage is append-only for the runtime role (TM-47): a report can't be changed or removed once made. 017 granted
-- update and delete (and 009's default privileges add them to every new table); take them back, as 016 does for
-- detection_backtests. Referential actions (ON DELETE SET NULL when a message is purged) run as the table owner, so
-- retention still works.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert on agent_usage to blueboard_app;
    revoke update, delete, truncate on agent_usage from blueboard_app;
  end if;
end
$$;
