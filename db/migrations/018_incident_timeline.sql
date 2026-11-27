-- WS4: attack timeline, attack graph and the emerging-threat playbook chain.
--
-- The timeline (GET /api/incidents/{id}/timeline, get_incident_timeline) and the attack graph (GET /api/incidents/{id}/graph,
-- get_incident_graph) are computed on read from incidents.data, messages and actions: they need no table. Events agents
-- add from hunting results are ordinary finding messages with payload.events, so they keep the message's author,
-- audit trail and retention.
--
-- The one new piece of state is a playbook run started from a threat intel finding (playbook scope: intel). Its
-- checklist steps are board questions in #intel with no incident, so they need their own run id and uniqueness.

create table if not exists ti_playbook_runs (
  id               uuid primary key default gen_random_uuid(),
  ti_finding_id    uuid not null references ti_findings(id) on delete cascade,
  playbook_id      text not null check (playbook_id ~ '^[a-z0-9][a-z0-9-]{0,40}$'),
  root_message_id  uuid references messages(id) on delete set null,
  started_by       uuid not null references principals(id),
  started_at       timestamptz not null default now(),
  all_posted       boolean not null default false,
  unique (ti_finding_id, playbook_id)
);
create index if not exists ti_playbook_runs_pending on ti_playbook_runs (started_at) where not all_posted;

-- One message per playbook step per intel run, so a retried unlock can never post a step twice. (The incident index
-- from 006 doesn't cover these: their incident_id is null, and nulls never collide in a unique index.)
create unique index if not exists messages_ti_checklist_step
  on messages ((payload #>> '{checklist,run}'), (payload #>> '{checklist,step}'))
  where type = 'question' and incident_id is null and payload #> '{checklist,run}' is not null;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert, update, delete on ti_playbook_runs to blueboard_app;
  end if;
end
$$;
