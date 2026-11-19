-- Threat intel and CVE sources (issues #15 to #21). Everything is off until a TI_*_ENABLED flag is set.

-- One row per source: on/off as last seen by the app, and how its last run went.
create table if not exists ti_sources (
  id             text primary key,             -- 'pwn.watch', 'cisa-kev', 'first-epss', 'nvd', 'osv', 'sentinel-ti', 'microsoft-ti', 'defender-tvm', 'cve.watch'
  name           text not null,
  enabled        boolean not null default false,
  last_fetch_at  timestamptz,
  last_status    text,                         -- 'ok' | 'error' | 'unavailable' | free text for the cve.watch re-check
  last_error     text,
  data_as_of     timestamptz,                  -- upstream generatedAt / catalogue date, for the freshness line
  updated_at     timestamptz not null default now()
);

-- Raw response bodies for the polite fetcher: TTL, ETag and Last-Modified revalidation.
create table if not exists ti_fetch_cache (
  url            text primary key,
  etag           text,
  last_modified  text,
  status         int not null,
  body           text not null,
  fetched_at     timestamptz not null
);

-- A flat, generic intel store. Every row says where it came from and when it was retrieved.
create table if not exists ti_records (
  id            uuid primary key default gen_random_uuid(),
  source        text not null,
  key           text not null,                 -- upstream id: pwn.watch slug, CVE id, GHSA id, indicator value
  kind          text not null check (kind in ('cve', 'incident', 'indicator', 'article', 'exposure')),
  title         text,
  severity      text,
  url           text,                          -- human page for this record (https only)
  source_url    text not null,                 -- the feed or API URL it was read from
  data          jsonb not null,
  found         boolean not null default true, -- false: the source was asked and has nothing (cached negative answer)
  published_at  timestamptz,
  updated_at    timestamptz,                   -- upstream modified time
  retrieved_at  timestamptz not null,
  first_seen_at timestamptz not null default now(),
  unique (source, key)
);
create index if not exists ti_records_source_retrieved on ti_records (source, retrieved_at desc);
create index if not exists ti_records_recent on ti_records (coalesce(updated_at, published_at, retrieved_at) desc) where found;

-- Lookup keys per record: CVE ids, GHSA ids, tags, products and indicator values.
create table if not exists ti_record_keys (
  record_id  uuid not null references ti_records(id) on delete cascade,
  key_kind   text not null,
  key_value  text not null,
  primary key (record_id, key_kind, key_value)
);
create index if not exists ti_record_keys_lookup on ti_record_keys (key_kind, key_value);

-- Watchlists: what outside intel is worth posting to #intel.
create table if not exists ti_watches (
  id          uuid primary key default gen_random_uuid(),
  kind        text not null check (kind in ('tag', 'product', 'cve', 'keyword')),
  value       text not null check (length(value) between 2 and 200),
  enabled     boolean not null default true,
  origin      text not null default 'manual' check (origin in ('default', 'manual', 'inventory')),
  label       text,
  created_at  timestamptz not null default now(),
  last_seen_at timestamptz,                    -- inventory watches: last nightly run that still found the product
  unique (kind, value)
);

-- Idempotence for board posts made from intel (hash of incident, date and title, as Crosswire does), and the
-- thread each upstream item posts into.
create table if not exists ti_posts (
  hash        text primary key,
  thread_key  text not null,
  message_id  uuid references messages(id),
  created_at  timestamptz not null default now()
);
create index if not exists ti_posts_thread on ti_posts (thread_key, created_at);

-- Shared request budget for rate-limited upstreams (NVD: 5 or 50 per rolling 30 s; advanced hunting), across instances.
create table if not exists ti_rate (
  bucket  text not null,
  at      timestamptz not null default now()
);
create index if not exists ti_rate_bucket_at on ti_rate (bucket, at);

insert into ti_watches (kind, value, origin, label) values
  ('tag', 'cisa-kev', 'default', 'CISA KEV'),
  ('tag', 'microsoft', 'default', 'Microsoft')
on conflict (kind, value) do nothing;

insert into ti_sources (id, name, last_status, last_error) values
  ('cve.watch', 'cve.watch', 'unavailable', 'Unavailable: parked domain, re-check later (see docs/ti/sources.md)')
on conflict (id) do nothing;
