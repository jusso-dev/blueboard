-- WS3: agent observability. Usage and hard budgets, verdict feedback and accuracy, MCP tool-call traces, agent risk.
-- Security boundary: agents only ever append usage rows for themselves (report_usage) and read feedback on their own
-- messages (get_agent_feedback). Budgets, top-ups, thresholds and settings are written by Board.Admin people over REST.
-- Traces hold a redacted, size-capped summary of each call's arguments, never result payloads or secrets.
-- The runtime role (blueboard_app) gets these tables through the default privileges set in 009; the grant below
-- covers databases where default privileges were not set.

-- Agent-reported LLM usage. Append-only: a report can't change or lower an earlier one; (principal, request_id) dedupes retries.
create table if not exists agent_usage (
  id                 bigserial primary key,
  principal_id       uuid not null references principals(id),
  model              text not null check (length(model) between 1 and 100),
  input_tokens       bigint not null default 0 check (input_tokens >= 0),
  output_tokens      bigint not null default 0 check (output_tokens >= 0),
  cache_read_tokens  bigint not null default 0 check (cache_read_tokens >= 0),
  cache_write_tokens bigint not null default 0 check (cache_write_tokens >= 0),
  cost_usd           numeric(14, 6) not null default 0 check (cost_usd >= 0),
  -- price_table: the board priced it; agent: the agent's own figure (model not in the price table); unpriced: neither.
  cost_source        text not null check (cost_source in ('price_table', 'agent', 'unpriced')),
  agent_cost_usd     numeric(14, 6) check (agent_cost_usd is null or agent_cost_usd >= 0),
  request_id         text check (request_id is null or length(request_id) <= 200),
  message_id         uuid references messages(id) on delete set null,
  claim_message_id   uuid references messages(id) on delete set null,
  incident_id        uuid references incidents(id) on delete set null,
  created_at         timestamptz not null default now()
);
create unique index if not exists agent_usage_request on agent_usage (principal_id, request_id) where request_id is not null;
create index if not exists agent_usage_principal_time on agent_usage (principal_id, created_at desc);
create index if not exists agent_usage_incident on agent_usage (incident_id) where incident_id is not null;

-- Board-side metering, rolled up per principal, UTC day and tool. Survives trace retention (budgets, risk baselines).
create table if not exists agent_metered_daily (
  principal_id  uuid not null references principals(id),
  day           date not null,
  tool          text not null,
  calls         int not null default 0,
  errors        int not null default 0,
  cost_usd      numeric(14, 6) not null default 0,
  primary key (principal_id, day, tool)
);

-- Hard budgets per agent (Board.Admin, people only). Any null limit is not enforced.
create table if not exists agent_budgets (
  principal_id    uuid primary key references principals(id),
  daily_usd       numeric(14, 4) check (daily_usd is null or daily_usd >= 0),
  monthly_usd     numeric(14, 4) check (monthly_usd is null or monthly_usd >= 0),
  daily_tokens    bigint check (daily_tokens is null or daily_tokens >= 0),
  monthly_tokens  bigint check (monthly_tokens is null or monthly_tokens >= 0),
  soft_pct        int not null default 80 check (soft_pct between 1 and 100),
  note            text check (note is null or length(note) <= 500),
  updated_by      uuid not null references principals(id),
  updated_at      timestamptz not null default now()
);

-- Temporary top-ups: extra USD/tokens on top of the budget until expires_at.
create table if not exists agent_budget_topups (
  id            uuid primary key default gen_random_uuid(),
  principal_id  uuid not null references principals(id),
  usd           numeric(14, 4) not null default 0 check (usd >= 0),
  tokens        bigint not null default 0 check (tokens >= 0),
  expires_at    timestamptz not null,
  reason        text not null check (length(reason) between 5 and 500),
  granted_by    uuid not null references principals(id),
  created_at    timestamptz not null default now()
);
create index if not exists agent_budget_topups_active on agent_budget_topups (principal_id, expires_at);

-- One row per agent and budget period: when the soft alert went out and whether the hard cap is in force. A new
-- period (UTC day / month) has no row, so a daily or monthly block lifts by itself; an admin change clears it early.
create table if not exists agent_budget_state (
  principal_id    uuid not null references principals(id),
  period          text not null check (period in ('day', 'month')),
  period_start    date not null,
  soft_alerted_at timestamptz,
  exceeded_at     timestamptz,
  cleared_at      timestamptz,
  detail          jsonb,
  primary key (principal_id, period, period_start)
);

-- Human feedback on an agent's verdict / finding / ioc, and outcomes recorded when an incident is resolved.
create table if not exists agent_feedback (
  id                        uuid primary key default gen_random_uuid(),
  message_id                uuid not null references messages(id) on delete cascade,
  agent_id                  uuid not null references principals(id),
  given_by                  uuid references principals(id),     -- null for resolution outcomes (the board)
  source                    text not null check (source in ('human', 'resolution')),
  verdict                   text not null check (verdict in ('correct', 'incorrect')),
  reason                    text check (reason is null or length(reason) <= 1000),
  agent_classification      text,
  corrected_classification  text check (corrected_classification is null or corrected_classification in ('truePositive', 'falsePositive', 'informationalExpectedActivity', 'unknown')),
  incident_id               uuid references incidents(id) on delete set null,
  created_at                timestamptz not null default now(),
  updated_at                timestamptz not null default now()
);
create unique index if not exists agent_feedback_human on agent_feedback (message_id, given_by) where source = 'human';
create unique index if not exists agent_feedback_resolution on agent_feedback (message_id, corrected_classification) where source = 'resolution';
create index if not exists agent_feedback_agent on agent_feedback (agent_id, created_at desc);

-- Incident resolutions already compared with the latest agent verdict (a re-classification is compared again).
create table if not exists agent_resolution_checks (
  incident_id     uuid not null references incidents(id) on delete cascade,
  classification  text not null,
  via             text not null,
  checked_at      timestamptz not null default now(),
  primary key (incident_id, classification)
);

-- Every MCP tool call: who, what (redacted argument summary), outcome, timing, result size, and what it was for.
create table if not exists agent_tool_calls (
  id                bigserial primary key,
  principal_id      uuid not null references principals(id),
  tool              text not null,
  status            text not null check (status in ('ok', 'error', 'forbidden', 'rate_limited', 'budget_blocked', 'secret_blocked', 'invalid')),
  args_summary      jsonb,
  kql               text check (kql is null or length(kql) <= 10000),
  error             text check (error is null or length(error) <= 300),
  duration_ms       int not null default 0,
  result_bytes      int not null default 0,
  message_id        uuid references messages(id) on delete set null,
  claim_message_id  uuid references messages(id) on delete set null,
  incident_id       uuid references incidents(id) on delete set null,
  -- true when the incident was inferred from the agent's recent calls rather than the call itself or its claim
  incident_inferred boolean not null default false,
  created_at        timestamptz not null default now()
);
create index if not exists agent_tool_calls_principal_time on agent_tool_calls (principal_id, created_at desc);
create index if not exists agent_tool_calls_incident on agent_tool_calls (incident_id, created_at) where incident_id is not null;
create index if not exists agent_tool_calls_claim on agent_tool_calls (claim_message_id) where claim_message_id is not null;
create index if not exists agent_tool_calls_message on agent_tool_calls (message_id) where message_id is not null;
create index if not exists agent_tool_calls_created on agent_tool_calls (created_at);

-- Latest risk score per agent (0-100) and the factors behind it. Recomputed on a timer.
create table if not exists agent_risk (
  principal_id    uuid primary key references principals(id),
  score           int not null check (score between 0 and 100),
  factors         jsonb not null default '[]',
  computed_at     timestamptz not null default now(),
  alerted_at      timestamptz,
  quarantined_at  timestamptz
);

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert, update, delete on agent_usage, agent_metered_daily, agent_budgets, agent_budget_topups,
      agent_budget_state, agent_feedback, agent_resolution_checks, agent_tool_calls, agent_risk to blueboard_app;
    grant usage, select on sequence agent_usage_id_seq, agent_tool_calls_id_seq to blueboard_app;
  end if;
exception when insufficient_privilege then
  raise notice 'blueboard: cannot grant agent observability tables to blueboard_app; relying on default privileges';
end
$$;
