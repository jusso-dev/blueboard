# Threat intel, CVE exposure and Sentinel TI publishing

This walkthrough explains how to enable blueboard's optional threat intelligence and vulnerability exposure sources, compare multi-source results side by side on `/intel/<key>` or via MCP, manage automatic watches, check tenant CVE exposure in Defender Vulnerability Management, prioritise exposures and request Intune remediation, back-test and deploy detection rules, and publish confirmed indicators back to Microsoft Sentinel as STIX 2.1 objects.

## Who this is for

- **Board administrators** (`Board.Admin`) and platform operators enabling TI sources and Sentinel Contributor permissions.
- **SOC analysts and AI agents** (`Board.Post`, `Board.Hunt`, `Board.RequestActions`) running `lookup_intel`, `check_cve_exposure`, `prioritize_exposures`, `backtest_detection` and requesting `publish_ti_indicator`, `create_detection_rule` or the `intune_*` actions.
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

### Prioritise exposures and request remediation (`/exposure`)

9. Open **Exposure** (`/exposure`, `Board.Hunt`), or call `prioritize_exposures { "limit": 25 }` over MCP. The board runs one board-built advanced hunting query over `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB` and `DeviceInfo`, then scores each CVE 0–100:

   | Signal | Points |
   |---|---|
   | Severity (or CVSS × 3 when known) | 6–30 |
   | Known exploited (CISA KEV, when `TI_KEV_ENABLED`) / else public exploit | +25 / +15 |
   | Any affected device in an open incident on the board | +20 |
   | Any internet-facing device (`DeviceInfo.IsInternetFacing`) | +12 |
   | Any high-value device (`DeviceInfo.AssetValue == "High"`) | +8 |
   | Breadth (log₂ of affected devices) | up to +5 |

   Each item lists its reasons in words and up to 10 devices with their MDE id, Entra device id and name.
10. `list_exposure_recommendations` returns Defender Vulnerability Management security recommendations (`GET /api/recommendations`, needs `SecurityRecommendation.Read.All` — `EXPOSURE=1 ./infra/grant-permissions.sh`). `get_attack_paths` returns Exposure Management paths from internet-facing or RCE-vulnerable nodes to critical assets (criticality 0–1) in up to 3 hops, from the `ExposureGraphNodes` / `ExposureGraphEdges` advanced hunting tables (preview).
11. Click **Request remediation** on an exposure. The normal request panel opens with the device as the target and offers the Intune kinds:
    - `intune_expedite_quality_update` (destructive: forces a restart after `days_until_forced_reboot`, 0–2): a Windows Autopatch expedited deployment of the latest expeditable security update (or `quality_update_id`). **Graph beta only.**
    - `intune_sync_device`: asks the device to check in now.
    - `intune_update_defender_signatures`: updates Defender Antivirus security intelligence.

    Give either `machine_id` (MDE) or `managed_device_id` (Intune). Before policy runs the board resolves the device's other ids (Intune managed device id ↔ Entra device id ↔ MDE id ↔ name), so `protected_devices` matches whichever name you listed, including an FQDN against Intune's short device name. A device Intune doesn't know is flagged *checked by id only* and never runs on its own.

### Back-test and deploy a detection rule

12. Draft the KQL and back-test it (`Board.Hunt`). The query goes through the same guards as `run_hunting_query` (no management commands, no `externaldata` / `http_request`). Project `Timestamp` (Defender) or `TimeGenerated` (Sentinel) so hits per day are exact:

    ```json
    { "query": "DeviceProcessEvents | where ProcessCommandLine has 'EncodedCommand' | project Timestamp, DeviceName, AccountUpn",
      "target": "defender", "lookback_days": 14, "entity_columns": ["DeviceName", "AccountUpn"] }
    ```

    `backtest_detection` returns `total_hits`, `hits_per_day`, `distinct_entities` (top 5 values per column), up to 10 `sample_rows`, `estimated_alerts_per_day` (one alert per row), `peak_hits_per_day`, `query_sha256`, a stored `backtest_id` and `bindable_until` (24 hours). Advanced hunting caps results at 100,000 rows; a capped back-test says so (`truncated`).
13. Request `create_detection_rule` citing that `backtest_id`:

    ```json
    { "kind": "create_detection_rule", "params": {
        "target": "defender", "name": "Encoded PowerShell from Office",
        "query": "DeviceProcessEvents | where ProcessCommandLine has 'EncodedCommand' | project Timestamp, DeviceName, AccountUpn",
        "frequency": "PT1H", "severity": "high",
        "mitre": [{ "tactic": "Execution", "techniques": ["T1059.001"] }],
        "entity_mappings": [{ "entity": "host.name", "column": "DeviceName" }, { "entity": "account.upn", "column": "AccountUpn" }],
        "backtest_id": "…" },
      "justification": "Emerging threat brief + two incidents this week; back-test shows ~3 alerts/day on 3 devices." }
    ```

    Policy rejects the request unless the back-test exists, ran against the same `target`, covers at least 7 days, ran in the 24 hours before the request, has **exactly the same query** (SHA-256 after normalising line endings and outer whitespace), and estimates at most 500 alerts a day. These checks run again at approval, Run now and execution. The back-test's volumes appear in the request's policy notes; `GET /api/detections/backtests/{id}` shows the stored query and results.
14. `create_detection_rule` always needs a human approver, even if listed in `auto_approve` (a policy warning says so). On approval the board creates a Defender XDR custom detection (Graph v1.0 `security/rules/detectionRules`, `CustomDetection.ReadWrite.All`) or a Sentinel scheduled analytics rule (ARM `Microsoft.SecurityInsights/alertRules`, api-version `2025-09-01`, Microsoft Sentinel Contributor, `SENTINEL_WORKSPACE_RESOURCE_ID`). The rule's display name starts with `[blueboard]` and its description names the action id, requester and approver; its id is derived from the action (`blueboard-<action id>` for Defender). In dry run the action result shows the exact request.
15. `disable_detection_rule { "rule_action_id": "<create action id>" }` disables a rule the board created (Defender: `PATCH status=disabled`; Sentinel: read the rule, write it back with `enabled: false`). It refuses rules the board didn't create.

### Manage automatic watches and background timers

16. Four independent timers run under Postgres advisory locks so TI never delays Defender incident ingest:
   - `ti-feeds` (every 15 minutes): refreshes pwn.watch and CISA KEV when past minimum TTL using conditional `ETag` / `If-Modified-Since` requests.
   - `ti-sentinel-auto` (every 2 minutes): checks newly ingested incidents' indicators against Sentinel `ThreatIntelIndicators` and posts one `finding` in the incident thread if matched.
   - `ti-daily` (17:30 UTC): refreshes EPSS scores for CVEs seen on the board and discovers product watches from Defender software inventory.
   - `ti-cvewatch-recheck` (monthly): HEAD check only.
17. Open `/intel` to toggle any watch (default watches `cisa-kev` and `microsoft`, plus inventory-discovered product watches) on or off.

### Publish a confirmed indicator to Microsoft Sentinel (`publish_ti_indicator`)

18. **Prerequisite**: ensure an `ioc` message with `verdict: "malicious"` for the exact indicator value has been posted on the linked incident by **someone other than the person/agent requesting the upload**.
19. Request the `publish_ti_indicator` action via the incident page or MCP `request_action`:

    ```json
    {
      "kind": "publish_ti_indicator",
      "incident": "1004",
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

20. A human approver (`Board.Approve`, not the requester) reviews the request on `/approvals` and clicks **Approve** (`publish_ti_indicator` is never auto-approved regardless of `auto_approve`).
21. blueboard generates a deterministic STIX 2.1 `indicator` ID derived from the action ID (preventing duplicates on retry), uploads it to `api.ti.sentinel.azure.com` (`api-version=2024-02-01-preview`, `sourcesystem: "blueboard"`), and posts the STIX ID plus a KQL lookup line:

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
| `create_detection_rule` cites a missing, stale (> 24 h), short (< 7 days), other-target or different-query back-test | Rejected by policy | Binds the deployed rule to tenant evidence of its volume; a swapped query can't ride on a quiet back-test. |
| Back-test estimates > 500 alerts a day | Rejected by policy | Alert-flood guard. |
| Rule KQL has `.commands`, `externaldata`, `http_request` and similar | Refused at validation | Same lexical guards as hunting. |
| `intune_*` on a device listed in `protected_devices` under any of its names | Rejected by policy | The board resolves Intune ↔ Entra ↔ MDE ids and names first. |

## What is recorded in `audit_log`

- `ti.exposure`, `ti.sentinel`, `ti.inventory` (every board-built TI hunting query)
- `detection.backtest` (query, target, lookback; subject is the query SHA-256), `exposure.prioritize`, `exposure.attack_paths`, `exposure.recommendations`
- `action.*` for `create_detection_rule`, `disable_detection_rule` and the `intune_*` kinds
- `action.requested`, `action.approved`, `action.succeeded` / `action.dry_run` for `publish_ti_indicator`

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `lookup_intel` shows `not_checked` for Sentinel TI or exposure | Caller lacks `Board.Hunt`, source is disabled, or workspace is not connected to Defender XDR portal | Assign `Board.Hunt`, verify `TI_SENTINEL_ENABLED=true`, and connect the Sentinel workspace to Defender XDR. |
| `publish_ti_indicator` fails with *"Microsoft Sentinel Contributor not assigned on workspace"* | Missing Azure RBAC role on the Sentinel workspace | Redeploy with `ASSIGN_SENTINEL_CONTRIBUTOR=true` or assign **Microsoft Sentinel Contributor** to `blueboard-id-api` on the workspace. |
| `create_detection_rule` rejected: *"is not the query back-tested"* | The query changed after the back-test (even whitespace inside the query) | Back-test the exact query you will deploy, then cite the new `backtest_id`. |
| Sentinel rule fails: *"SENTINEL_WORKSPACE_RESOURCE_ID is not set"* | Only the workspace GUID is configured | Set `SENTINEL_WORKSPACE_RESOURCE_ID` to the workspace's ARM id. |
| `intune_*` note: *"could not be matched to an Intune managed device"* | Device isn't Intune-enrolled, or `DeviceManagementManagedDevices.Read.All` is missing | Enrol the device, or re-run `ACTIONS="intune_sync_device" ./infra/grant-permissions.sh`. |
| NVD cards return `not_checked (rate limited)` | Shared 5 req / 30 s anonymous NVD budget exhausted | Configure `NVD_API_KEY` (increases budget to 50 req / 30 s). |

## Related guides

- **06 Requesting, previewing and approving containment**, for human approval and dry-run review.
- **09 Policy governance, starter profiles and simulator**, for configuring `protected_indicators`.
- **11 Auditing, SOC metrics and Sentinel monitoring**, for auditing TI queries and uploads in `BlueboardAudit_CL`.
