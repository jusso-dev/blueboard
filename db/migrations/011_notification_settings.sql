-- Notifications beyond approvals: board messages (an agent mentions or asks someone, replies in their thread, posts a
-- verdict or finding; a new incident; an action's result), and settings that decide which events notify whom.
-- Where notices go (webhook URL, Teams URL, mailbox, secrets) stays in app settings, never in the database.
--
-- The runtime role (blueboard_app) gets the new table through the default privileges set in 009; the grant below
-- repeats it for a server where those belong to a different migrating role, and is skipped where the role doesn't exist.

-- One row per (action, event, sink) for approver notices, as before, and one per (message, event, sink, recipient)
-- for message notices. recipient is the person's handle for a per-person notice, null for a board-wide one.
-- held: waiting for the recipient's quiet hours to end (send_after); skipped: settings said nobody wants it.
alter table notifications alter column action_id drop not null;
alter table notifications add column if not exists message_id uuid references messages(id);
alter table notifications add column if not exists recipient text;
alter table notifications add column if not exists send_after timestamptz;
alter table notifications drop constraint if exists notifications_action_id_event_sink_key;
create unique index if not exists notifications_action_event_sink
  on notifications (action_id, event, sink) where action_id is not null;
create unique index if not exists notifications_message_event_sink_recipient
  on notifications (message_id, event, sink, coalesce(recipient, '')) where message_id is not null;
alter table notifications drop constraint if exists notifications_status_check;
alter table notifications add constraint notifications_status_check
  check (status in ('sending', 'sent', 'failed', 'held', 'skipped'));
alter table notifications drop constraint if exists notifications_subject_check;
alter table notifications add constraint notifications_subject_check
  check (action_id is not null or message_id is not null);
create index if not exists notifications_held on notifications (send_after) where status = 'held';
create index if not exists notifications_recent on notifications (created_at desc);

-- Board-wide defaults (principal_id null, admin-editable) and one row per person with only the fields they set.
-- settings is a partial NotificationSettings document; the board lays it over the built-in defaults.
create table if not exists notification_settings (
  principal_id  uuid references principals(id),
  settings      jsonb not null check (jsonb_typeof(settings) = 'object'),
  updated_at    timestamptz not null default now(),
  updated_by    uuid references principals(id)
);
create unique index if not exists notification_settings_principal
  on notification_settings (coalesce(principal_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- A person's sign-in name (Entra preferred_username, usually their UPN), so a notice can carry an address a
-- downstream router can use. Recorded at sign-in; null for agents and dev principals.
alter table principals add column if not exists username text;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert, update, delete on notification_settings to blueboard_app;
  end if;
exception
  when insufficient_privilege then
    raise notice 'blueboard: cannot grant notification_settings to blueboard_app; relying on default privileges';
end
$$;
