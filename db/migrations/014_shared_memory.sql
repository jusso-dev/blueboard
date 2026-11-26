-- Shared SOC memory store for agents and human analysts (environment facts, known-benign baselines, asset context,
-- recurring threat patterns, team procedures and temporary notices such as change freezes).
-- Security boundary: agents may write/update unverified memories; only humans may verify, pin, edit verified entries,
-- or archive another participant's memory.

create table if not exists shared_memories (
  id                 uuid primary key default gen_random_uuid(),
  key                text not null unique check (length(key) between 2 and 120),
  category           text not null default 'general'
                     check (category in ('environment', 'baseline', 'asset', 'threat', 'procedure', 'preference', 'general')),
  title              text not null check (length(title) between 3 and 200),
  content            text not null check (length(content) between 5 and 4000),
  tags               text[] not null default '{}',
  entities           text[] not null default '{}',
  confidence         double precision check (confidence is null or (confidence >= 0 and confidence <= 1)),
  verified           boolean not null default false,
  verified_by        uuid references principals(id),
  verified_at        timestamptz,
  pinned             boolean not null default false,
  archived           boolean not null default false,
  source_incident_id uuid references incidents(id) on delete set null,
  source_message_id  uuid references messages(id) on delete set null,
  expires_at         timestamptz,
  created_by         uuid not null references principals(id),
  updated_by         uuid not null references principals(id),
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  tsv                tsvector generated always as (
                       setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
                       setweight(to_tsvector('simple', coalesce(key, '')), 'A') ||
                       setweight(to_tsvector('english', coalesce(content, '')), 'B')
                     ) stored
);

create index if not exists shared_memories_active_rank
  on shared_memories (pinned desc, verified desc, updated_at desc)
  where not archived;
create index if not exists shared_memories_category on shared_memories (category) where not archived;
create index if not exists shared_memories_tags on shared_memories using gin (tags);
create index if not exists shared_memories_entities on shared_memories using gin (entities);
create index if not exists shared_memories_tsv on shared_memories using gin (tsv);

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert, update, delete on shared_memories to blueboard_app;
  end if;
end
$$;
