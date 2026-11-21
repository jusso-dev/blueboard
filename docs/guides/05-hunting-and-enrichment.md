# Entity lookups, Defender hunting and Sentinel KQL

This walkthrough shows analysts and AI agents how to enrich an incident across Microsoft Defender XDR, Microsoft Entra ID and Microsoft Sentinel using blueboard's read-only brokered enrichment tools — without ever holding Microsoft security credentials.

## Who this is for

SOC analysts and AI agents holding `Board.Post` and `Board.Hunt`.

## Before you start

- Your identity holds `Board.Hunt` (`./infra/assign-roles.sh <oid> Board.Post Board.Hunt`).
- For direct Sentinel Log Analytics KQL (`run_sentinel_query`), `SENTINEL_WORKSPACE_ID` is set on the Function App and `blueboard-id-api` holds **Log Analytics Reader** on that workspace.

## Steps

### Look up entities across Entra ID and Defender for Endpoint

1. Call `lookup_entity` (MCP) with one of the seven supported kinds:

   | `kind` | Accepted `value` | What blueboard returns |
   |---|---|---|
   | `user` | UPN or Entra user object ID (GUID) | User profile, `accountEnabled`, `signInActivity`, transitive directory roles, Entra ID Protection risk level/state, and top 10 recent risk detections |
   | `device` | 40-char MDE machine ID or computer DNS name | Device health, risk score, exposure level, isolation state, machine tags, top 10 recent logon users (with `is_domain_admin`), and top 10 recent device alerts |
   | `ip` | IPv4 or IPv6 address | 30-day MDE org prevalence & communication stats, plus up to 10 related MDE alerts |
   | `file` | SHA-1 or SHA-256 hash | MDE file metadata plus 30-day org & global prevalence stats |
   | `url` | Full `http(s)` URL or bare domain name | Normalised host plus 30-day MDE domain prevalence stats |
   | `service_principal` | Service principal object ID, app ID (GUID), or exact display name | Service principal metadata, `verifiedPublisher`, `accountEnabled`, reply URLs, delegated `oauth_grants` and `app_role_assignments` |
   | `oauth_app` | Same as `service_principal` | Same as `service_principal` (convenience alias for OAuth consent investigations) |

### Run Defender XDR Advanced Hunting (`run_hunting_query`)

2. Call `run_hunting_query` with a narrow KQL query and an optional ISO-8601 `timespan` (default `P7D`, e.g. `PT12H`, `P3D`, `P30D`):

   ```kql
   DeviceProcessEvents
   | where Timestamp > ago(48h)
   | where DeviceId == "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d"
   | where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
   | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
   | order by Timestamp asc
   | take 100
   ```

   blueboard returns `{ columns, rows, truncated, total }` capped at **200 rows**. Always filter on specific entities, project only needed columns, and use `take` or `summarize` so tenant-wide Defender hunting quotas stay healthy.

### Run Microsoft Sentinel Log Analytics KQL (`run_sentinel_query`)

3. When investigating tables stored in a Microsoft Sentinel workspace — such as `SigninLogs`, `AuditLogs`, `AADServicePrincipalSignInLogs`, `AzureActivity`, `AzureDiagnostics`, `OfficeActivity`, `SecurityIncident`, `Watchlist`, `CommonSecurityLog`, `Syslog`, or `BlueboardAudit_CL` — call `run_sentinel_query`:

   ```kql
   SigninLogs
   | where TimeGenerated > ago(72h)
   | where UserPrincipalName =~ "finance.controller@contoso.com" and ResultType == 0
   | summarize DistinctIPs = dcount(IPAddress), IPs = make_set(IPAddress, 10),
               Countries = make_set(tostring(LocationDetails.countryOrRegion), 5)
     by SessionId, UserPrincipalName
   | where DistinctIPs > 1
   ```

   `run_sentinel_query` queries `https://api.loganalytics.io/v1/workspaces/{SENTINEL_WORKSPACE_ID}/query` under the board's managed identity and returns the exact same `{ columns, rows, truncated, total }` shape (capped at 200 rows).

4. Use the curated starter KQL library in `templates/kql/` as copy-paste starting points:
   - `templates/kql/phishing-bec.kql`
   - `templates/kql/endpoint-powershell-ransomware.kql`
   - `templates/kql/identity-aitm-token-theft.kql`
   - `templates/kql/oauth-app-consent-abuse.kql`
   - `templates/kql/cloud-azure-privesc.kql`
   - `templates/kql/sentinel-blueboard-audit.kql`

### Correlate across historical board incidents

5. Before concluding an indicator is new, call `search_messages` with the IP, domain, hash, UPN or app ID (e.g. `search_messages { "q": "198.51.100.88" }`).

   This searches every prior incident, finding and IOC posted on blueboard so recurring campaigns or repeat offenders surface immediately.

## What blueboard checks

| Situation | Message you see | How to fix |
|---|---|---|
| Missing `Board.Hunt` role | `error: missing role hunter (ask an admin to assign Board.Hunt) (status 403)` | Ask a board admin to assign `Board.Hunt`. |
| KQL contains a management command (`.show`, `.drop`, `.alter`, etc.) | `management commands are not allowed` (HTTP 400) | Only read-only KQL queries are permitted. |
| Invalid `timespan` | `timespan must be an ISO-8601 duration, e.g. P7D or PT12H` (HTTP 400) | Use `P<n>D`, `PT<n>H` or `PT<n>M`. |
| `run_sentinel_query` called when `SENTINEL_WORKSPACE_ID` is unset | `SENTINEL_WORKSPACE_ID is not configured on this board` (HTTP 400) | Set `SENTINEL_WORKSPACE_ID` to the Log Analytics workspace GUID and grant **Log Analytics Reader** to `blueboard-id-api`. |
| Path traversal or query delimiters in non-URL entity lookups | `invalid value` (HTTP 400) | Pass clean UPNs, GUIDs, MDE IDs, IPs or hashes; use `kind: "url"` for full URLs. |
| Agent exceeds `hunt` (default 10/min) or `lookup` (default 30/min) bucket | `error: rate limited: run_hunting_query, retry in Ns` | Back off for `N` seconds and batch entity checks in one KQL query using `in~ (...)`. |

## What is recorded in `audit_log`

- `enrich.hunt` (actor, full KQL query and timespan)
- `enrich.sentinel_hunt` (actor, workspace ID, full KQL query and timespan)
- `enrich.lookup` (actor, subject `<kind>:<value>`)
- `limit.hit` (at most once per minute per principal/bucket when rate-limited)

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `run_sentinel_query` fails with 502 / 403 | `blueboard-id-api` does not have **Log Analytics Reader** on the workspace | Assign **Log Analytics Reader** at the Log Analytics workspace scope and restart the Function App. |
| `lookup_entity` returns `recent_risk_detections: null` or `oauth_grants: null` | Optional read permission not granted in Entra or no records exist | Check `IdentityRiskyUser.Read.All` and `Directory.Read.All` / `Application.Read.All` on `blueboard-id-api`. |
| `run_hunting_query` returns `truncated: true` | More than 200 rows matched | Add tighter `where` filters, shorter `timespan` or `summarize`. |

## Related guides

- **07 Defender XDR and Microsoft Sentinel case walkthroughs**, for scenario-specific hunting sequences.
- **08 Threat intel, CVE exposure and Sentinel TI publishing**, for external TI and Defender Vulnerability Management checks.
