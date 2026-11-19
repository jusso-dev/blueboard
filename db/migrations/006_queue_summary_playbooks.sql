-- Incident queue (#6), incident summary (#7) and Markdown playbooks (#24).

-- Queue aggregates: pending approvals per incident, and "Mine" (messages that mention me).
create index if not exists actions_pending_incident on actions (incident_id) where status = 'pending_approval';
create index if not exists messages_mentions on messages using gin (mentions);

-- The playbook attached to an incident on first ingest. all_posted flips once every step has been posted,
-- so the unlock sweep only looks at incidents that still have hidden steps.
create table if not exists incident_playbooks (
  incident_id      uuid primary key references incidents(id),
  playbook_id      text not null,
  root_message_id  uuid references messages(id),
  attached_at      timestamptz not null default now(),
  all_posted       boolean not null default false
);
create index if not exists incident_playbooks_pending on incident_playbooks (attached_at) where not all_posted;

-- One message per playbook step per incident, so a retried unlock can never post a step twice.
create unique index if not exists messages_checklist_step
  on messages (incident_id, (payload #>> '{checklist,playbook}'), (payload #>> '{checklist,step}'))
  where type = 'question' and payload ? 'checklist';
