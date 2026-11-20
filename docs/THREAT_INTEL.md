# Threat intel and CVE feeds

blueboard can pull outside threat intel and CVE feeds, check them against this tenant, and show what every source says about one CVE or indicator side by side. People see it on `/intel` and `/intel/<CVE or indicator>`; agents get the same through MCP. Everything is off until you turn a source on.

The list of sources, their licences and status is in [ti/sources.md](ti/sources.md).

## Turn sources on

Set Function App settings (or the matching `infra/deploy.sh` environment variables, which pass them to Bicep):

| Setting | Source | Extra permission |
|---|---|---|
| `TI_PWNWATCH_ENABLED=true` | pwn.watch | none (outbound https to `pwn.watch`) |
| `TI_KEV_ENABLED=true` | CISA KEV | none (`www.cisa.gov`) |
| `TI_EPSS_ENABLED=true` | FIRST EPSS | none (`api.first.org`) |
| `TI_NVD_ENABLED=true`, optional `NVD_API_KEY` | NVD | none (`services.nvd.nist.gov`) |
| `TI_OSV_ENABLED=true` | OSV.dev and GitHub advisories | none (`api.osv.dev`) |
| `TI_SENTINEL_ENABLED=true` | Sentinel TI | none: `ThreatHunting.Read.All` is already granted |
| `TI_EXPOSURE_ENABLED=true` | Defender Vulnerability Management | none: `ThreatHunting.Read.All` |
| `TI_MSTI_ENABLED=true` | Microsoft Threat Intelligence | `ThreatIntelligence.Read.All`: run `TI_MSTI=1 ./infra/grant-permissions.sh …` |
| `TI_CVEWATCH_ENABLED` | cve.watch | refused at start-up: the domain is parked |

`TI_EXPOSURE_SOURCE` is reserved for the MDE vulnerabilities API (`api`, with `Vulnerability.Read.All`); only `kql` is implemented today.

With every source off, nothing is fetched and `/intel` lists the flags above.

## How fetching works

All outside feeds go through one fetcher (`api/Blueboard.Api/Intel/TiFetcher.cs`, ported from Crosswire's `politeFetch`):

- User-Agent `blueboard/<version> (+https://github.com/jusso-dev/blueboard)`.
- A raw-body cache in `ti_fetch_cache`. Inside a source's minimum TTL nothing goes on the network; after it, `If-None-Match` and `If-Modified-Since` are sent and a `304` reuses the cache.
- https only, and only to the exact hosts that source is allowed. Redirects are followed only to https on the same host, at most 3 hops. Anything else fails the fetch and nothing is cached.
- 30 second timeout, 25 MB size cap (`TI_MAX_RESPONSE_BYTES`) checked on `Content-Length` and on the streamed bytes.
- At most 2 retries on `429` or `503`, waiting for `Retry-After` (capped at 60 seconds).
- No Microsoft token ever passes through it. Microsoft calls use `MsClient`, which sends the managed identity's token only to exact Microsoft origins.

NVD and board-built hunting queries also take from shared request budgets (`ti_rate`): NVD 5 or 50 requests per rolling 30 seconds, hunting 20 queries a minute, so threat intel can't use up the advanced hunting quota analysts and agents need.

## Schedules

Timer triggers, each under its own Postgres advisory lock so threat intel never holds up incident ingest:

| Timer | When | What |
|---|---|---|
| `ti-feeds` | every 15 minutes | pwn.watch and KEV, each skipped inside its TTL |
| `ti-sentinel-auto` | every 2 minutes | new incidents from the last day: one Sentinel TI check each, one finding only if something matched |
| `ti-daily` | 17:30 UTC | EPSS batch for CVEs seen on the board, automatic watches from Defender inventory |
| `ti-cvewatch-recheck` | monthly | HEAD request to cve.watch; records the status only |

Each source is isolated: a failure is written to `ti_sources.last_error`, shown on `/intel`, and never stops Defender incident ingest.

## Data model

Migration `007_threat_intel.sql`:

- `ti_sources`: on or off, last run, last status and error, data date (for "pwn.watch data from 8 Nov 2026 (11 days old)").
- `ti_fetch_cache`: raw bodies, ETag, Last-Modified.
- `ti_records`: one flat row per source and upstream key, with `url` (human page), `source_url` (the feed or API it was read from), `retrieved_at`, and `found` (false caches a "no record" answer).
- `ti_record_keys`: lookup keys per record (CVE, GHSA, tag, product, vendor, CWE, indicator values).
- `ti_watches`: tag, product, cve and keyword watches. `cisa-kev` and `microsoft` are on by default; Defender inventory adds product watches labelled "from Defender inventory". Any watch can be turned off on `/intel`.
- `ti_posts`: idempotence for board posts (a hash of incident, date and title for pwn.watch changes) and the thread each item posts into.

## What gets posted

All posts are `finding` messages by the board, @mention nobody, and credit their source.

- **pwn.watch**: a change to an incident that matches an enabled watch posts once in `#intel`, with title, severity, patch status, fixed versions, CVEs and a link. Later changes to the same incident reply in its thread. The first run only records what already exists, so turning the source on doesn't flood the channel. At most 20 posts per run; the rest follow on the next run.
- **Exposure**: a CVE newly added to KEV, or a new pwn.watch incident, that is present in Defender inventory posts once with device counts (needs `TI_EXPOSURE_ENABLED`).
- **Sentinel TI**: a match on a new incident's indicators posts once in the incident's thread.
- **Post to #intel** on `/intel/<key>` posts a summary of every card as the person who pressed it.

## Lookups

`/intel/<key>` and the MCP tool `lookup_intel { key }` take a CVE id, GHSA id, IP, domain, URL, email or file hash, and return one card per source that can answer that kind of key:

- `found`, `not_found` or `not_checked`. A source that is off, failing, rate limited, or needs a role the caller doesn't have is `not_checked` with a reason. It never reads as "no data".
- Every card has `source`, `url`, `retrieved_at` and its attribution.
- Agree / differ lines compare exploitation, severity and dates across the found cards. They are deterministic; no model is involved.
- Related board incidents and messages that mention the key.

Tenant sources (Sentinel TI, Microsoft TI, exposure) use the board's Microsoft permissions, so they need `Board.Hunt`. `lookup_intel` and `check_cve_exposure` need `Board.Hunt` for the same reason, and every board-built hunting query is written to `audit_log` (`ti.exposure`, `ti.sentinel`, `ti.inventory`).

`check_cve_exposure { cve_ids }` returns, per CVE, `cve, devices, device_names` (at most 20, with `device_names_truncated`), `software, severity, remediation, in_open_incidents, retrieved_at, age_seconds`. Results are cached 6 hours. It is a read and never triggers an action.

KQL is built only from values that pass validation (`CVE-\d{4}-\d{4,}` for CVEs; per-kind rules for indicators) and written as escaped string literals. Sentinel TI uses the `ThreatIntelIndicators` table; the legacy `ThreatIntelligenceIndicator` table stopped receiving data after 31 July 2025. Workspaces not connected to the Defender portal can't be reached through advanced hunting; that is a known limitation.

## In the UI

- Any CVE id in a message, including inside bold text, links to `/intel/<CVE>`, with a badge when the board already holds KEV or EPSS for it: "Known exploited · due 2021-12-24", "ransomware", "EPSS 97% (p99)". Words, not colour alone. Badges come from the store only: rendering a message never fetches anything.
- EPSS is shown as "likelihood of exploitation in the next 30 days", as FIRST defines it. It is a probability, not a verdict.
- The incident page and `get_incident` list the CVEs in the incident's alerts with KEV and EPSS.

## Untrusted content

Feed text is written by others, and could be written by an attacker. It is stored as data, shown as quoted text through the safe Markdown renderer (no HTML, http(s) links only), and returned to agents inside an `untrusted_data` object with a notice to treat it as data. The pwn.watch `agentBrief` is fetched only when a person opens it and is shown quoted; it is never given to an agent as instructions. Board posts built from feed text are flattened to one line per field and can't @mention anyone.

## Publishing to Sentinel (`publish_ti_indicator`)

A destructive catalog action that uploads one confirmed indicator to Microsoft Sentinel threat intelligence through the STIX objects upload API (`api.ti.sentinel.azure.com`, `api-version=2024-02-01-preview`). **The API is in preview** under the Azure Preview Supplemental Terms.

- Params: `kind` (ip, domain, url, sha256, sha1, md5, email), `value`, `confidence` 0–100, `valid_days` 1–90 (default 30), `tlp` (white, green, amber, red; default amber), `description`.
- It builds a STIX 2.1 `indicator` with a pattern such as `[domain-name:value = 'bad.example']` (values validated for their kind and escaped), `valid_from`, `valid_until`, `confidence`, labels, the TLP marking, `external_references` back to the board incident, and `created_by_ref` to a fixed blueboard identity object. `sourcesystem` is `blueboard`. The indicator id is derived from the action id, so a retry can't create a second indicator.
- Policy: it must be linked to an incident, and the value must appear in an `ioc` message on that incident with verdict `malicious`, posted by someone other than the requester; `protected_indicators` applies. It is never auto-approved, whatever `auto_approve` says.
- Dry run (`BROKER_EXECUTE=false`) posts the exact request (URL and STIX JSON) that would be sent. A live run posts the STIX id and a KQL line to find it in `ThreatIntelIndicators`.
- Token audience: Azure Resource Manager (`https://management.azure.com/.default`). The upload origin is on `MsClient`'s exact-origin allowlist.
- Needs `SENTINEL_WORKSPACE_ID` (the workspace id GUID; Bicep fills it from `sentinelWorkspaceResourceId`) and the Azure role **Microsoft Sentinel Contributor** on that workspace. Without the role the action fails with "Microsoft Sentinel Contributor not assigned on workspace <id>". Assign it with Bicep (`assignSentinelContributor=true`, or `ASSIGN_SENTINEL_CONTRIBUTOR=true ./infra/deploy.sh`), or by hand:

  ```sh
  az role assignment create --assignee-object-id <board-identity-principal-id> --assignee-principal-type ServicePrincipal \
    --role "Microsoft Sentinel Contributor" --scope <workspace-resource-id>
  ```

Revoking a published indicator is a follow-up action, not built yet.

## Local demo

Set `TI_FIXTURES_DIR` to `api/Blueboard.Api.Tests/Fixtures/ti` (absolute path) with the `TI_*_ENABLED` flags you want, and every source, including the Microsoft ones, is served from the recorded fixtures. `TI_FIXTURES_DIR` is refused in Azure. The demo phishing incident (`seed-dev --sample`) has a URL that matches the Sentinel TI fixture, and the exposure fixture puts CVE-2021-44228 on the sample incident's device.

## Not tested live

Sentinel TI, Microsoft Threat Intelligence, Defender exposure and the STIX upload could not be called from a tenant while building this; they are tested against hand-built fixtures that follow Microsoft's published schemas. Before relying on them, run one lookup of each in a test tenant, and one live `publish_ti_indicator` followed by `ThreatIntelIndicators | where SourceSystem == "blueboard"`.
