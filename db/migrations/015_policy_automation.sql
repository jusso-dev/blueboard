-- Conditional automation, admin policy overrides, playbook triggers, the automation kill switch and auto-revert (WS1).
--
-- policy.json stays the ceiling: these tables only ever narrow it, and the board re-validates every row against the
-- loaded file when it reads them (a row that no longer fits is ignored, never widened). Tightening writes straight to
-- policy_overrides / playbook_triggers; loosening writes a policy_changes row that a second, different Board.Admin must
-- approve (decided_by <> requested_by is a CHECK, like the two-person rule on actions). Every change is audited.

-- One effective override per action kind (or per playbook trigger / the automation pause). version bumps on every
-- write so the rule id shown on the board ("isolate_device@v7") names exactly which setting ran an action.
create table if not exists policy_overrides (
  kind        text primary key,
  setting     jsonb not null,                -- { mode, confirm_target, rule }
  version     bigint not null default 1,
  updated_by  uuid not null references principals(id),
  updated_at  timestamptz not null default now(),
  change_id   uuid                           -- the policy_changes row that applied it (null: applied directly as a tightening)
);

-- Playbook auto-attach triggers. File triggers (from playbooks/*.md) appear with source = 'file' once an admin edits
-- them; custom triggers are source = 'custom'.
create table if not exists playbook_triggers (
  id           text primary key check (id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
  playbook_id  text not null,
  source       text not null check (source in ('file', 'custom')),
  match        jsonb not null,               -- { severities, sources, titles, categories, techniques }
  priority     int not null default 0 check (priority between -100 and 1000),
  enabled      boolean not null default true,
  version      bigint not null default 1,
  updated_by   uuid not null references principals(id),
  updated_at   timestamptz not null default now()
);

-- Every requested change: tightenings are applied (status 'applied') at once; loosenings wait ('pending') for a
-- second admin. The checks below are the SQL backstop for the two-person rule and for decisions on expired rows.
create table if not exists policy_changes (
  id            uuid primary key default gen_random_uuid(),
  target        text not null check (target ~ '^(kind|trigger|automation):[a-z0-9_-]{1,64}$'),
  before        jsonb,                        -- the override before (null: none)
  after         jsonb,                        -- the requested override (null: reset / remove)
  loosening     boolean not null,
  reason        text not null check (length(reason) between 5 and 500),
  status        text not null default 'pending' check (status in ('pending', 'applied', 'denied', 'expired', 'superseded')),
  requested_by  uuid not null references principals(id),
  requested_at  timestamptz not null default now(),
  expires_at    timestamptz not null,
  decided_by    uuid references principals(id),
  decided_at    timestamptz,
  decision_note text check (decision_note is null or length(decision_note) <= 2000),
  -- A loosening is applied only by someone other than the person who asked for it.
  constraint policy_changes_second_admin check (not loosening or status <> 'applied' or (decided_by is not null and decided_by <> requested_by)),
  -- Nobody approves their own change, even to deny it.
  constraint policy_changes_not_self check (decided_by is null or decided_by <> requested_by or status in ('expired', 'superseded', 'applied'))
);
create index if not exists policy_changes_pending on policy_changes (target) where status = 'pending';
create index if not exists policy_changes_recent on policy_changes (requested_at desc);
-- At most one pending change per target: a newer request supersedes the older one.
create unique index if not exists policy_changes_one_pending on policy_changes (target) where status = 'pending';

-- Reject approving an expired change, whoever does it, and never let the requester apply their own loosening even if
-- a code path forgets the check.
create or replace function policy_changes_guard() returns trigger language plpgsql as $$
begin
  if old.status <> 'pending' and new.status <> old.status then
    raise exception 'policy change % is already %', old.id, old.status using errcode = 'check_violation';
  end if;
  if old.status = 'pending' and new.status = 'applied' and old.expires_at <= now() then
    raise exception 'policy change % has expired', old.id using errcode = 'check_violation';
  end if;
  return new;
end
$$;
drop trigger if exists policy_changes_guard on policy_changes;
create trigger policy_changes_guard before update on policy_changes for each row execute function policy_changes_guard();

-- Actions: which rule ran it on its own, and the automatic revert.
alter table actions add column if not exists auto_rule text;
alter table actions add column if not exists revert_after_minutes int check (revert_after_minutes is null or revert_after_minutes between 5 and 10080);
alter table actions add column if not exists revert_at timestamptz;
alter table actions add column if not exists revert_state text check (revert_state is null or revert_state in ('scheduled', 'kept', 'reverting', 'reverted', 'failed'));
-- set null on delete: retention may purge one side of an original/revert pair before the other.
alter table actions add column if not exists revert_action_id uuid references actions(id) on delete set null;
alter table actions add column if not exists revert_of uuid references actions(id) on delete set null;
create index if not exists actions_revert_due on actions (revert_at) where revert_state = 'scheduled';
-- Caps count automatic runs per kind (tenant-wide per hour, and per incident).
create index if not exists actions_auto_rule on actions (kind, created_at) where auto_rule is not null;
-- One revert per original action, whoever files it (timer, Revert now, two instances at once).
create unique index if not exists actions_one_revert on actions (revert_of) where revert_of is not null;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert, update on policy_overrides, playbook_triggers, policy_changes to blueboard_app;
    grant delete on policy_overrides, playbook_triggers to blueboard_app;
    -- policy_changes is history: the runtime role can't delete it.
    revoke delete, truncate on policy_changes from blueboard_app;
  end if;
end
$$;
