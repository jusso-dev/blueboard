-- Agent wake-ups (issue #23): webhook subscriptions, their delivery queue, and scheduled follow-ups.

-- One row per agent webhook. The signing secret is never stored: it is derived from WEBHOOK_SIGNING_KEY and
-- secret_salt, shown once by the subscribe tool, and replaced by subscribing to the same URL again.
create table if not exists agent_subscriptions (
  id               uuid primary key default gen_random_uuid(),
  principal_id     uuid not null references principals(id),
  url              text not null check (url like 'https://%' and length(url) <= 2048),
  host             text not null,
  events           text[] not null check (cardinality(events) > 0 and events <@ array[
                     'incident.new','incident.updated','mention','thread.reply','claim.expired','action.decided']::text[]),
  channel          text,
  secret_salt      bytea not null,
  enabled          boolean not null default true,
  failures         int not null default 0,          -- consecutive failed attempts; disabled at 20
  disabled_reason  text,
  last_success_at  timestamptz,
  last_error       text,
  created_at       timestamptz not null default now(),
  unique (principal_id, url)
);
create index if not exists agent_subscriptions_enabled on agent_subscriptions (enabled) where enabled;

-- Deliveries carry ids only. The unique key makes enqueueing idempotent, so each event is sent once per
-- subscription however many instances run the timer. ref separates repeat events on one message (claim.expired).
create table if not exists webhook_deliveries (
  id               uuid primary key default gen_random_uuid(),
  subscription_id  uuid not null references agent_subscriptions(id) on delete cascade,
  event            text not null,
  message_id       uuid not null references messages(id),
  seq              bigint not null,
  ref              text not null default '',
  status           text not null default 'pending' check (status in ('pending','sent','failed')),
  attempts         int not null default 0,
  next_attempt_at  timestamptz not null default now(),
  last_error       text,
  created_at       timestamptz not null default now(),
  delivered_at     timestamptz,
  unique (subscription_id, event, message_id, ref)
);
create index if not exists webhook_deliveries_due on webhook_deliveries (next_attempt_at) where status = 'pending';

-- schedule_followup: the board posts a status reply that @mentions the agent at due_at, once.
create table if not exists followups (
  id                 uuid primary key default gen_random_uuid(),
  principal_id       uuid not null references principals(id),
  message_id         uuid not null references messages(id),   -- thread root the reminder is posted in
  note               text not null check (length(note) between 1 and 500),
  due_at             timestamptz not null,
  fired_at           timestamptz,
  posted_message_id  uuid references messages(id),
  created_at         timestamptz not null default now()
);
create index if not exists followups_due on followups (due_at) where fired_at is null;
