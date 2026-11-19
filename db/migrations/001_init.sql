-- blueboard initial schema
create extension if not exists pgcrypto;

create table if not exists principals (
  id            uuid primary key default gen_random_uuid(),
  handle        text not null unique,
  display_name  text not null,
  kind          text not null check (kind in ('agent', 'human', 'system')),
  entra_oid     text unique,          -- object id (user or service principal)
  entra_app_id  text,                 -- appid / azp for workload identities
  roles         text[] not null default '{}',
  enabled       boolean not null default true,
  description   text,
  created_at    timestamptz not null default now(),
  last_seen_at  timestamptz
);

create table if not exists channels (
  id          uuid primary key default gen_random_uuid(),
  name        text not null unique check (name ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
  topic       text not null default '',
  created_at  timestamptz not null default now()
);

create table if not exists incidents (
  id               uuid primary key default gen_random_uuid(),
  graph_id         text not null unique,       -- Defender XDR / Sentinel incident id
  display_name     text not null,
  severity         text not null,
  status           text not null,
  classification   text,
  determination    text,
  assigned_to      text,
  alert_count      int not null default 0,
  web_url          text,
  created_at_src   timestamptz,
  updated_at_src   timestamptz,
  data             jsonb not null,             -- full Graph payload incl. alerts/evidence
  first_seen_at    timestamptz not null default now(),
  last_synced_at   timestamptz not null default now()
);

create table if not exists messages (
  id                uuid primary key default gen_random_uuid(),
  seq               bigserial unique,           -- monotonic cursor for polling
  channel_id        uuid not null references channels(id),
  author_id         uuid not null references principals(id),
  parent_id         uuid references messages(id),
  incident_id       uuid references incidents(id),
  type              text not null check (type in (
                      'chat','finding','question','ioc','action_request',
                      'action_result','verdict','status','incident')),
  body              text not null check (length(body) <= 20000),
  payload           jsonb,
  mentions          text[] not null default '{}',
  claim_state       text not null default 'open' check (claim_state in ('open','claimed','done')),
  claimed_by        uuid references principals(id),
  claimed_at        timestamptz,
  claim_expires_at  timestamptz,
  created_at        timestamptz not null default now()
);
create index if not exists messages_channel_seq on messages (channel_id, seq);
create index if not exists messages_incident_seq on messages (incident_id, seq);
create index if not exists messages_parent on messages (parent_id);
create index if not exists messages_claim on messages (claim_state, claim_expires_at);

create table if not exists actions (
  id                uuid primary key default gen_random_uuid(),
  kind              text not null,
  params            jsonb not null,
  incident_id       uuid references incidents(id),
  request_message_id uuid references messages(id),
  requested_by      uuid not null references principals(id),
  justification     text not null,
  status            text not null check (status in (
                      'pending_approval','approved','denied','running','succeeded','failed','rejected')),
  requires_approval boolean not null,
  policy_notes      text[] not null default '{}',
  decided_by        uuid references principals(id),
  decided_at        timestamptz,
  decision_note     text,
  result            jsonb,
  error             text,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create index if not exists actions_status on actions (status, created_at);

create table if not exists audit_log (
  id          bigserial primary key,
  at          timestamptz not null default now(),
  actor_id    uuid references principals(id),
  event       text not null,
  subject     text,
  detail      jsonb
);

create table if not exists kv_state (
  key    text primary key,
  value  jsonb not null,
  updated_at timestamptz not null default now()
);

insert into channels (name, topic) values
  ('incidents',   'New and updated Defender XDR / Sentinel incidents (posted by the ingest poller)'),
  ('triage',      'Severity, scope and true/false positive discussion'),
  ('intel',       'Enrichment: entity context, threat intel, hunting results, IOCs'),
  ('containment', 'Containment proposals and brokered action requests'),
  ('eradication', 'Root cause, eradication and recovery'),
  ('general',     'Anything else')
on conflict (name) do nothing;

insert into principals (handle, display_name, kind, roles, description) values
  ('board', 'Blueboard', 'system', '{}', 'Ingest poller and action broker')
on conflict (handle) do nothing;
