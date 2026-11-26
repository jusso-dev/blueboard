-- Slack-style reactions, typing indicators, and actions approved on a person's instruction.
--
-- The runtime role (blueboard_app) gets these tables through the default privileges set in 009. The grant below
-- repeats them for a server where 009's default privileges belong to a different migrating role; it is skipped,
-- like 009, where the role doesn't exist.

-- One row per (message, person, emoji). Idempotent add: insert ... on conflict do nothing.
create table if not exists message_reactions (
  message_id    uuid not null references messages(id),
  principal_id  uuid not null references principals(id),
  emoji         text not null check (length(emoji) between 1 and 32),
  created_at    timestamptz not null default now(),
  primary key (message_id, principal_id, emoji)
);
create index if not exists message_reactions_message on message_reactions (message_id);

-- Who is typing where. One row per principal and composer: a thread (root_id) or a channel's top level (root_id null).
-- Rows are short-lived (until = now() + a few seconds); readers filter on until and writers sweep expired rows.
create table if not exists typing (
  principal_id  uuid not null references principals(id),
  channel_id    uuid not null references channels(id),
  incident_id   uuid references incidents(id),
  root_id       uuid references messages(id),
  until         timestamptz not null
);
create unique index if not exists typing_scope
  on typing (principal_id, channel_id, coalesce(root_id, '00000000-0000-0000-0000-000000000000'::uuid));
create index if not exists typing_root on typing (root_id) where root_id is not null;

-- The person's board message whose instruction counted as the approval (policy act_on_instruction). One action per
-- kind per instruction, so an agent can't replay one "go ahead" for a second action of the same kind.
alter table actions add column if not exists on_behalf_of uuid references messages(id);
create unique index if not exists actions_on_behalf_of_kind on actions (on_behalf_of, kind) where on_behalf_of is not null;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert, update, delete on message_reactions, typing to blueboard_app;
  end if;
exception
  when insufficient_privilege then
    raise notice 'blueboard: cannot grant reactions/typing to blueboard_app; relying on default privileges';
end
$$;
