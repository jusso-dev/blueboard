-- Operations: approver notifications (#3), participant admin and the broker pause (#10).

-- One row per (action, event, sink) is the idempotency key: a notification is claimed by inserting its row
-- before it is sent, so each event goes to each sink once even with several Function App instances.
create table if not exists notifications (
  id          bigserial primary key,
  action_id   uuid references actions(id),
  event       text not null,               -- requested | reminder:<n> | expired | interrupted | failed
  sink        text not null check (sink in ('teams', 'mail', 'webhook')),
  status      text not null default 'sending' check (status in ('sending', 'sent', 'failed')),
  attempts    int not null default 0,
  error       text,
  created_at  timestamptz not null default now(),
  sent_at     timestamptz,
  unique (action_id, event, sink)
);
create index if not exists notifications_retry on notifications (status, created_at) where status = 'failed';

-- Disabling a principal needs a reason, and the board shows who did it and when.
alter table principals add column if not exists disabled_reason text;
alter table principals add column if not exists disabled_by uuid references principals(id);
alter table principals add column if not exists disabled_at timestamptz;

-- An action approved while the broker is paused is held: it stays 'approved', the recovery sweep skips it,
-- and only an approver's "Run now" (after unpausing) sends it.
alter table actions add column if not exists held_at timestamptz;
drop index if exists actions_recover;
create index if not exists actions_recover on actions (status, updated_at) where status in ('approved', 'running') and held_at is null;
create index if not exists messages_author_created on messages (author_id, created_at);
create index if not exists actions_requested_by_created on actions (requested_by, created_at);
