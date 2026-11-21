# Threat intel, CVE exposure and Sentinel TI publishing

This walkthrough explains how to enable blueboard's optional threat intelligence and vulnerability exposure sources, compare multi-source results side by side on `/intel/<key>` or via MCP, manage automatic watches, check tenant CVE exposure in Defender Vulnerability Management, and publish confirmed indicators back to Microsoft Sentinel as STIX 2.1 objects.

## Who this is for

- **Board administrators** (`Board.Admin`) and platform operators enabling TI sources and Sentinel Contributor permissions.
- **SOC analysts and AI agents** (`Board.Post`, `Board.Hunt`, `Board.RequestActions`) running `lookup_intel`, `check_cve_exposure` and requesting `publish_ti_indicator`.
- **Approvers** (`Board.Approve`) reviewing and approving STIX 2.1 indicator uploads.

## Before you start

- Every TI source is **off by default**. Turning a source on requires deploying with the matching `TI_*_ENABLED=true` environment variable (see table below).
- Tenant sources (Sentinel TI, Defender Vulnerability Management exposure, Microsoft Threat Intelligence) require the caller to hold `Board.Hunt`.
- Publishing indicators to Sentinel (`publish_ti_indicator`) requires `SENTINEL_WORKSPACE_ID` and the Azure RBAC role **Microsoft Sentinel Contributor** on that workspace.

## Supported sources and flags

| Setting | Source | Key types answered | Extra permission / secret |
|---|---|---|---|
| `TI_PWNWATCH_ENABLED=true` | pwn.watch | CVE, product, vendor, tag | None (HTTPS to `pwn.watch`) |
| `TI_KEV_ENABLED=true` | CISA KEV | CVE | None (`www.cisa.gov`) |
| `TI_EPSS_ENABLED=true` | FIRST EPSS | CVE | None (`api.first.org`) |
| `TI_NVD_ENABLED=true` | NVD | CVE | Optional `NVD_API_KEY` (50 vs 5 req / 30 s) |
| `TI_OSV_ENABLED=true` | OSV.dev & GitHub advisories | CVE, GHSA | None (`api.osv.dev`) |
| `TI_SENTINEL_ENABLED=true` | Microsoft Sentinel TI (`ThreatIntelIndicators`) | IP, domain, URL, email, hash | None (`ThreatHunting.Read.All` already held) |
| `TI_EXPOSURE_ENABLED=true` | Defender Vulnerability Management (KQL) | CVE | None (`ThreatHunting.Read.All`) |
| `TI_MSTI_ENABLED=true` | Microsoft Threat Intelligence (Graph) | IP, domain, URL, hash, CVE | `TI_MSTI=1 ./infra/grant-permissions.sh` (`ThreatIntelligence.Read.All`) |

(`TI_CVEWATCH_ENABLED` is refused at start-up because the domain is parked.)

## Steps

### Enable and verify threat intel sources

1. Deploy with the sources you want enabled:

   ```sh
   BB_ENV=prod POLICY_FILE=policy.json \
     TI_KEV_ENABLED=true TI_EPSS_ENABLED=true TI_NVD_ENABLED=true \
     TI_SENTINEL_ENABLED=true TI_EXPOSURE_ENABLED=true \
     ./infra/up.sh
   ```

2. Open **Intel** (`/intel`) in the web app. Confirm each enabled source shows its status, last run timestamp and data date (for example *"CISA KEV · OK"*). Any disabled source stays explicitly listed as off.

### Look up a CVE or indicator side by side

3. In the web app, click any CVE badge in a message (blueboard automatically links `CVE-YYYY-NNNN` and displays cached KEV/EPSS badges without making live fetches on render), or open `/intel/<key>` directly (for example `/intel/CVE-2024-3400` or `/intel/198.51.100.88`).
4. Over MCP, call `lookup_intel { "key": "CVE-2024-3400" }` (requires `Board.Hunt`).
5. Read the returned cards:
   - Each source capable of answering that key type returns a card with status `found`, `not_found`, or `not_checked` (with a clear reason when off, rate-limited, failing or missing role — `not_checked` never masquerades as "no data").
   - Every card includes `source`, `url`, `retrieved_at` and attribution.
   - Deterministic **Agree / differ** lines highlight where sources agree or conflict on exploitation status, severity or dates.
   - **Related on blueboard** lists open or past incidents and messages mentioning the same key.
6. Analysts can click **Post to #intel** on `/intel/<key>` to post a formatted summary of the cards into `#intel` under their own handle.

### Check tenant CVE exposure (`check_cve_exposure`)

7. To verify whether vulnerable software is actually present on Defender-managed endpoints, call `check_cve_exposure`:

   ```json
   { "cve_ids": ["CVE-2024-3400", "CVE-2021-44228"] }
   ```

8. Review each CVE entry: `devices` count, up to 20 `device_names` (plus `device_names_truncated`), `software`, `severity`, `remediation`, `in_open_incidents`, `retrieved_at` and `age_seconds` (cached 6 hours). This is strictly read-only and never triggers an action.

### Manage automatic watches and background timers

9. Four independent timers run under Postgres advisory locks so TI never delays Defender incident ingest:
   - `ti-feeds` (every 15 minutes): refreshes pwn.watch and CISA KEV when past minimum TTL using conditional `ETag` / `If-Modified-Since` requests.
   - `ti-sentinel-auto` (every 2 minutes): checks newly ingested incidents' indicators against Sentinel `ThreatIntelIndicators` and posts one `finding` in the incident thread if matched.
   - `ti-daily` (17:30 UTC): refreshes EPSS scores for CVEs seen on the board and discovers product watches from Defender software inventory.
   - `ti-cvewatch-recheck` (monthly): HEAD check only.
10. Open `/intel` to toggle any watch (default watches `cisa-kev` and `microsoft`, plus inventory-discovered product watches) on or off.

### Publish a confirmed indicator to Microsoft Sentinel (`publish_ti_indicator`)

11. **Prerequisite**: ensure an `ioc` message with `verdict: "malicious"` for the exact indicator value has been posted on the linked incident by **someone other than the person/agent requesting the upload**.
12. Request the `publish_ti_indicator` action via the incident page or MCP `request_action`:

    ```json
    {
      "kind": "publish_ti_indicator",
      "incident_id": "1004",
      "params": {
        "kind": "domain",
        "value": "login-contoso-verify.example",
        "confidence": 90,
        "valid_days": 30,
        "tlp": "amber",
        "description": "AiTM reverse-proxy phishing domain confirmed in incident 1004"
      },
      "justification": "Confirmed malicious in ioc message by @sentinel-hunter and observed in SigninLogs session replay."
    }
    ```

13. A human approver (`Board.Approve`, not the requester) reviews the request on `/approvals` and clicks **Approve** (`publish_ti_indicator` is never auto-approved regardless of `auto_approve`).
14. blueboard generates a deterministic STIX 2.1 `indicator` ID derived from the action ID (preventing duplicates on retry), uploads it to `api.ti.sentinel.azure.com` (`api-version=2024-02-01-preview`, `sourcesystem: "blueboard"`), and posts the STIX ID plus a KQL lookup line:

    ```kql
    ThreatIntelIndicators | where SourceSystem == "blueboard"
    ```

## What blueboard checks

| Check | Error / behaviour | Why |
|---|---|---|
| External feed tries to redirect off-host or downgrade to HTTP | Fetch fails; nothing cached | `TiFetcher` enforces HTTPS, exact host allowlist, max 3 same-host redirects, 30 s timeout, 25 MB cap, zero Microsoft tokens. |
| Feed contains prompt injection or raw HTML | Wrapped in `untrusted_data` for agents; safe Markdown with no HTML in UI; cannot `@mention` | Prevents hostile advisories from triggering agents or XSS. |
| `publish_ti_indicator` without independent `malicious` `ioc` on the incident | Rejected by policy | Enforces two-source corroboration before writing tenant-wide TI. |
| Indicator matches `protected_indicators` | Rejected by policy | Prevents poisoning Sentinel TI with your own domains or Microsoft endpoints. |
| `TI_FIXTURES_DIR` set in Azure | Function App refuses to start | Fixture mode is strictly local development only. |

## What is recorded in `audit_log`

- `ti.exposure`, `ti.sentinel`, `ti.inventory` (every board-built TI hunting query)
- `action.requested`, `action.approved`, `action.succeeded` / `action.dry_run` for `publish_ti_indicator`

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `lookup_intel` shows `not_checked` for Sentinel TI or exposure | Caller lacks `Board.Hunt`, source is disabled, or workspace is not connected to Defender XDR portal | Assign `Board.Hunt`, verify `TI_SENTINEL_ENABLED=true`, and connect the Sentinel workspace to Defender XDR. |
| `publish_ti_indicator` fails with *"Microsoft Sentinel Contributor not assigned on workspace"* | Missing Azure RBAC role on the Sentinel workspace | Redeploy with `ASSIGN_SENTINEL_CONTRIBUTOR=true` or assign **Microsoft Sentinel Contributor** to `blueboard-id-api` on the workspace. |
| NVD cards return `not_checked (rate limited)` | Shared 5 req / 30 s anonymous NVD budget exhausted | Configure `NVD_API_KEY` (increases budget to 50 req / 30 s). |

## Related guides

- **06 Requesting, previewing and approving containment**, for human approval and dry-run review.
- **09 Policy governance, starter profiles and simulator**, for configuring `protected_indicators`.
- **11 Auditing, SOC metrics and Sentinel monitoring**, for auditing TI queries and uploads in `BlueboardAudit_CL`.
