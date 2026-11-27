-- Third-party connectors (docs/INTEGRATIONS.md § Okta and § Ticketing): Okta identity links for cross-IdP policy alias
-- checks and the incident page, ServiceNow / Jira ticket links, inbound webhook replay protection, connector health.
-- No credential is ever stored here: connector secrets are app settings (Key Vault references in production).

-- Ticketing systems post into incident threads as their own principal. kind 'integration' is neither a person nor the
-- board: it can never approve actions (Broker.DecideAsync needs a human) and its posts are untrusted data.
alter table principals drop constraint if exists principals_kind_check;
alter table principals add constraint principals_kind_check check (kind in ('agent', 'human', 'system', 'integration'));

insert into principals (handle, display_name, kind, roles, description) values
  ('servicenow', 'ServiceNow', 'integration', '{poster}', 'Inbound ServiceNow ticket updates (untrusted data; cannot approve actions)'),
  ('jira', 'Jira', 'integration', '{poster}', 'Inbound Jira ticket updates (untrusted data; cannot approve actions)')
on conflict (handle) do nothing;

-- Every name one outside identity is known by (Okta user id, login, primary and secondary email). PolicyEngine links
-- these with the incident's Entra users (UPN ↔ object id), so a protected UPN also protects the Okta user with that
-- login or email. Refreshed by lookups, enrichment and every Okta write.
create table if not exists identity_links (
  provider      text not null check (provider in ('okta')),
  external_id   text not null check (length(external_id) between 1 and 100),
  login         text check (length(login) <= 320),
  email         text check (length(email) <= 320),
  second_email  text check (length(second_email) <= 320),
  display_name  text check (length(display_name) <= 200),
  status        text check (length(status) <= 40),
  context       jsonb,                        -- last lookup (status, factors, last login, groups, admin roles): never a credential
  refreshed_at  timestamptz not null default now(),
  primary key (provider, external_id)
);
create index if not exists identity_links_login on identity_links (lower(login));
create index if not exists identity_links_email on identity_links (lower(email));
create index if not exists identity_links_second_email on identity_links (lower(second_email));

-- One ticket per incident per system. Board → ticket sync writes structured events (never raw message bodies).
create table if not exists ticket_links (
  id                  uuid primary key default gen_random_uuid(),
  incident_id         uuid not null references incidents(id) on delete cascade,
  system              text not null check (system in ('servicenow', 'jira')),
  external_id         text not null check (length(external_id) between 1 and 100),  -- ServiceNow sys_id / Jira issue id
  external_key        text not null check (length(external_key) between 1 and 100), -- INC0010001 / SOC-42
  url                 text check (length(url) <= 2048),
  reason              text not null check (length(reason) <= 200),
  created_at          timestamptz not null default now(),
  last_synced_at      timestamptz,
  resolved_synced_at  timestamptz,
  last_error          text check (length(last_error) <= 500),
  unique (incident_id, system),
  unique (system, external_id)
);
create index if not exists ticket_links_key on ticket_links (system, external_key);

-- Inbound ticket webhooks: a nonce is accepted once inside the signature's 5-minute window (replay protection). Rows are
-- written only after the signature verifies, so unauthenticated callers can't fill the table; the sync timer purges
-- rows older than a day.
create table if not exists inbound_nonces (
  system       text not null check (system in ('servicenow', 'jira')),
  nonce        text not null check (length(nonce) between 16 and 128),
  received_at  timestamptz not null default now(),
  primary key (system, nonce)
);
create index if not exists inbound_nonces_received on inbound_nonces (received_at);

-- Health for the Admin → Connectors page and the setup check. Error text is the vendor's summary, never a token.
create table if not exists connector_status (
  connector      text primary key check (connector in ('okta', 'servicenow', 'jira')),
  last_ok_at     timestamptz,
  last_error_at  timestamptz,
  last_error     text check (length(last_error) <= 500),
  last_sync_at   timestamptz,
  updated_at     timestamptz not null default now()
);

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'blueboard_app') then
    grant select, insert, update, delete on identity_links, ticket_links, inbound_nonces, connector_status to blueboard_app;
  end if;
end
$$;
