-- ntfy (phone push) as a fourth notification sink next to teams, mail and webhook. Where it points (NOTIFY_NTFY_URL)
-- and its access token (NOTIFY_NTFY_TOKEN) stay in app settings, never in the database.
--
-- 005 declared the check inline on the column, so PostgreSQL named it notifications_sink_check. Drop and re-add it
-- so the migration can run again safely.
alter table notifications drop constraint if exists notifications_sink_check;
alter table notifications add constraint notifications_sink_check
  check (sink in ('teams', 'mail', 'webhook', 'ntfy'));
