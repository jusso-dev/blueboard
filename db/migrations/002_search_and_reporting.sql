-- Full-text search over message bodies and IOC values, plus indexes for search filters and reporting.

-- IOC values are tokenised with the 'simple' config so hashes, IPs and domains are not stemmed.
alter table messages add column if not exists search tsvector
  generated always as (
    setweight(to_tsvector('english', coalesce(body, '')), 'A') ||
    setweight(to_tsvector('simple', coalesce(jsonb_path_query_array(payload, '$.indicators[*].value')::text, '')), 'B')
  ) stored;

create index if not exists messages_search on messages using gin (search);
create index if not exists messages_created on messages (created_at desc);
create index if not exists messages_author_seq on messages (author_id, seq);
create index if not exists messages_type_incident on messages (type, incident_id, created_at);
create index if not exists actions_incident on actions (incident_id, created_at);
create index if not exists incidents_first_seen on incidents (first_seen_at desc);
