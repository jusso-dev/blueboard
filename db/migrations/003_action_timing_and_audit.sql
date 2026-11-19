-- Execution timing (reporting, stuck-action recovery) and audit_log indexes (admin reporting).
alter table actions add column if not exists started_at timestamptz;
alter table actions add column if not exists finished_at timestamptz;
create index if not exists actions_recover on actions (status, updated_at) where status in ('approved', 'running');
create index if not exists audit_log_at on audit_log (at desc);
create index if not exists audit_log_actor_at on audit_log (actor_id, at desc);
