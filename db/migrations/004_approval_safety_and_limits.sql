-- Approval safety (issue #9) and per-principal rate limits (issue #5).

-- New action states: approved_once (1 of 2 approvals), expired (not decided in time).
alter table actions drop constraint if exists actions_status_check;
alter table actions add constraint actions_status_check check (status in (
  'pending_approval','approved_once','approved','denied','running','succeeded','failed','rejected','expired'));

alter table actions add column if not exists expires_at timestamptz;
alter table actions add column if not exists approvals_required int not null default 1 check (approvals_required between 1 and 2);
-- Requests already waiting get the default 4 hour window from the upgrade, not from when they were filed.
update actions set expires_at = now() + interval '4 hours' where status = 'pending_approval' and expires_at is null;
create index if not exists actions_expiry on actions (expires_at) where status in ('pending_approval', 'approved_once');
create index if not exists actions_incident_open on actions (incident_id) where status in ('pending_approval', 'approved_once');

-- One row per human approval. The primary key stops the same person approving twice.
create table if not exists action_approvals (
  action_id    uuid not null references actions(id),
  approver_id  uuid not null references principals(id),
  note         text,
  at           timestamptz not null default now(),
  primary key (action_id, approver_id)
);

-- Token buckets, one per principal and bucket (post, hunt, lookup, action_request, claim). Shared by every instance.
create table if not exists rate_buckets (
  principal_id  uuid not null references principals(id),
  bucket        text not null,
  tokens        double precision not null,
  refilled_at   timestamptz not null default now(),
  limited_at    timestamptz,             -- last time a call was refused (limit.hit is audited at most once a minute)
  primary key (principal_id, bucket)
);
