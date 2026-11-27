-- Detection back-tests (backtest_detection) and their binding to create_detection_rule.
-- A back-test is run by the board itself (agents never write this table): the query, a SHA-256 of the query, the
-- target it ran against and the volumes it found. create_detection_rule must cite a back-test whose query hash and
-- target match the rule it deploys and that ran in the 24 hours before the request (Actions/DetectionRules.cs).

create table if not exists detection_backtests (
  id                 uuid primary key default gen_random_uuid(),
  requested_by       uuid not null references principals(id),
  target             text not null check (target in ('defender', 'sentinel')),
  query              text not null check (length(query) between 5 and 10000),
  query_sha256       text not null check (query_sha256 ~ '^[0-9a-f]{64}$'),
  lookback_days      int not null check (lookback_days between 1 and 30),
  entity_columns     text[] not null default '{}',
  total_hits         bigint not null check (total_hits >= 0),
  undated_hits       bigint not null default 0 check (undated_hits >= 0),
  hits_per_day       jsonb not null default '[]',
  distinct_entities  jsonb not null default '{}',
  sample_rows        jsonb not null default '[]',
  est_alerts_per_day double precision not null check (est_alerts_per_day >= 0),
  peak_hits_per_day  bigint not null default 0,
  created_at         timestamptz not null default now()
);

create index if not exists detection_backtests_hash on detection_backtests (query_sha256, target, created_at desc);
create index if not exists detection_backtests_created on detection_backtests (created_at desc);

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    -- Append-only for the runtime role: a back-test is evidence an approver relies on, so it is never edited.
    -- Migration 009's default privileges also grant update and delete on new tables; take those back.
    grant select, insert on detection_backtests to blueboard_app;
    revoke update, delete, truncate on detection_backtests from blueboard_app;
  end if;
end
$$;
