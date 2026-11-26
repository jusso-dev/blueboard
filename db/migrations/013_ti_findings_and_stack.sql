-- General chat channel guarantee, tech stack / vendor watches, and structured Threat Intel findings table.

-- Ensure #general exists for team chat and give it a clear topic if it still has the old default.
insert into channels (name, topic) values
  ('general', 'Team chat, handovers, and general discussion')
on conflict (name) do update
  set topic = case when channels.topic in ('', 'Anything else') then excluded.topic else channels.topic end;

-- Expand ti_watches.kind so teams can explicitly configure their tech stack and vendors alongside products, tags, CVEs and keywords.
alter table ti_watches drop constraint if exists ti_watches_kind_check;
alter table ti_watches add constraint ti_watches_kind_check
  check (kind in ('stack', 'vendor', 'product', 'tag', 'cve', 'keyword'));

-- Structured threat intel findings posted by bots/agents and analysts, tied to the org's tech stack and watchlists.
create table if not exists ti_findings (
  id              uuid primary key default gen_random_uuid(),
  title           text not null check (length(title) between 3 and 300),
  summary         text not null check (length(summary) between 5 and 8000),
  severity        text not null check (severity in ('critical', 'high', 'medium', 'low', 'informational')),
  status          text not null default 'new' check (status in ('new', 'reviewing', 'mitigated', 'dismissed')),
  confidence      double precision check (confidence is null or (confidence >= 0 and confidence <= 1)),
  tech_stack      text[] not null default '{}',
  matched_watches text[] not null default '{}',
  cves            text[] not null default '{}',
  indicators      jsonb not null default '[]'::jsonb,
  source          text not null check (length(source) between 1 and 200),
  source_url      text,
  recommendation  text check (recommendation is null or length(recommendation) <= 2000),
  author_id       uuid not null references principals(id),
  message_id      uuid references messages(id) on delete set null,
  dedupe_key      text unique,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create index if not exists ti_findings_created on ti_findings (created_at desc);
create index if not exists ti_findings_status_sev on ti_findings (status, severity, created_at desc);
create index if not exists ti_findings_stack on ti_findings using gin (tech_stack);
create index if not exists ti_findings_cves on ti_findings using gin (cves);

-- Ensure runtime role has access when role separation is enabled (db/migrations/009).
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert, update, delete on ti_findings to blueboard_app;
  end if;
end
$$;
