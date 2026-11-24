# Defender XDR and Microsoft Sentinel case walkthroughs

This walkthrough provides seven end-to-end Microsoft Defender XDR, Microsoft Sentinel and Microsoft Purview investigation and response recipes on blueboard. Each case matches a bundled playbook in `playbooks/` and starter KQL queries in `templates/kql/`, with reproducible fixtures in `templates/incidents/` so your SOC can rehearse every workflow safely in dry-run mode.

## Who this is for

SOC analysts, incident commanders, approvers and AI agent engineers building or tuning Defender XDR and Sentinel response workflows.

## Before you start

- Familiarity with **03 Working a Defender XDR and Sentinel incident**, **05 Entity lookups, Defender hunting and Sentinel KQL** and **06 Requesting, previewing and approving containment**.
- Optional rehearsal: load fixtures from `templates/incidents/` against your local dev/demo board (`./scripts/demo.sh up`) or attach the relevant playbook manually on a test incident.

---

## Case 1: Phishing campaign and malicious attachment / URL (MDO + MDE)

- **Playbook**: `phishing` (`playbooks/phishing.md`, priority 40)
- **KQL template**: `templates/kql/phishing-bec.kql`
- **Sample incident**: built-in `seed-dev --sample`

### Steps

1. **Scope delivery and clicks** (`run_hunting_query` over `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`): find all recipients of the sender domain, `NetworkMessageId`, subject cluster, and whether any user clicked through.
2. **Check endpoint execution**: if a user opened an attachment or clicked a payload URL, query `DeviceProcessEvents` and `DeviceFileEvents` for the user's device and call `lookup_entity` (`kind: "url"`, `kind: "file"`).
3. **Check Threat Intel**: call `lookup_intel` on the sender IP, phishing URL/domain and attachment SHA-256 to check Sentinel TI and MSTI.
4. **Post structured findings & IOCs**: post `ioc` messages (`verdict: "malicious"`) for confirmed phishing URLs, sender IPs and attachment hashes, plus a `verdict` (`truePositive`).
5. **Propose containment** (`request_action`):
   - `purge_email` (`messages: [{ "network_message_id": "...", "recipient": "user@contoso.com" }]`, `action: "softDelete"`) for every affected recipient.
   - `block_indicator` (`indicator_type: "url" | "domain" | "sha256"`, `value`, `title`, `expires_in_days: 90`).
   - If credentials were entered: `revoke_sessions` and `reset_password`.
   - `publish_ti_indicator` (optional, once another participant has posted a `malicious` `ioc` on the incident).
6. **Close loop**: once approvers execute containment, request `update_incident` (`status: "resolved"`, `classification: "truePositive"`, `determination: "phishing"`) and `add_incident_comment`.

---

## Case 2: Business Email Compromise (BEC) and AiTM token theft

- **Playbook**: `bec-aitm-token-theft` (`playbooks/bec-aitm-token-theft.md`, priority 20)
- **KQL template**: `templates/kql/identity-aitm-token-theft.kql`
- **Sample fixture**: `templates/incidents/bec-aitm-inbox-rule.json`

### Steps

1. **Correlate replayed sessions** (`run_sentinel_query` on `SigninLogs`): group by `SessionId` over 72 hours to spot tokens minted from one ASN/device and replayed from a residential proxy or attacker VPS (`198.51.100.88`).
2. **Enrich the user**: call `lookup_entity { "kind": "user", "value": "<upn-or-oid>" }` to check directory roles, Entra ID Protection risk state, and recent risk detections.
3. **Hunt persistence** (`run_hunting_query` on `CloudAppEvents` + `run_sentinel_query` on `AuditLogs` and `OfficeActivity`): inspect `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, new MFA method registrations (`Register security info`), and OAuth app consents.
4. **Assess blast radius**: check `EmailEvents` for outbound emails sent from the mailbox during the hijack window (vendor payment redirection, internal phishing) and `CloudAppEvents` for SharePoint/OneDrive downloads.
5. **Propose containment** (`request_action`):
   - `confirm_user_compromised` (Entra OID GUID) — elevates Entra risk so Conditional Access blocks the session immediately.
   - `revoke_sessions` (UPN or OID).
   - `disable_user` (if the mailbox is actively sending fraud mail or passwordless/MFA persistence was added) or `reset_password`.
   - `block_indicator` for the AiTM proxy IP and reverse-proxy phishing domain.
6. **Eradication**: remove malicious inbox rules and rogue MFA methods in Exchange/Entra, then record verification in `#eradication`.

---

## Case 3: Hands-on-keyboard ransomware, LSASS dump and lateral movement

- **Playbook**: `ransomware-lateral-movement` (`playbooks/ransomware-lateral-movement.md`, priority 10)
- **KQL template**: `templates/kql/endpoint-powershell-ransomware.kql`
- **Sample data**: Trigger via live Defender incident sync or `./scripts/demo.sh up` (`templates/incidents/` ships `bec-aitm-inbox-rule.json`, `oauth-app-consent.json`, `azure-keyvault-privesc.json` and `purview-dlp-insider-exfil.json`)

### Steps

1. **Verify host criticality first**: call `lookup_entity { "kind": "device", "value": "<machine-id-or-hostname>" }` to inspect `tags`, `is_domain_admin` logon users, exposure level and existing isolation status. Never isolate a domain controller or hypervisor (policy `protected_devices` blocks them, and isolating an unlisted tier-0 server can cause an outage).
2. **Scope process tree and credential access** (`run_hunting_query`): query `DeviceProcessEvents`, `DeviceNetworkEvents` and `DeviceLogonEvents` for `lsass.exe` access, `vssadmin delete shadows`, `wbadmin`, encoded PowerShell, SMB/WinRM/RDP fan-out, and newly created services or scheduled tasks.
3. **Preserve volatile forensics and contain fast**:
   - `collect_investigation_package` (typically auto-approved when target is in evidence).
   - `isolate_device` (`isolation_type: "Selective"` or `"Full"`) for every confirmed compromised workstation/member server.
   - `stop_and_quarantine_file` (SHA-1) for active payload binaries still running on unaffected or partially affected hosts.
   - `restrict_app_execution` for hosts suspected of staging where full network isolation would disrupt production.
   - `tag_device` (`tag: "IR-Contained"`, `action: "Add"`) to track containment across Defender.
4. **Contain compromised accounts**: for any account whose credentials were present on the LSASS-dumped host, propose `revoke_sessions` and `disable_user` (or `reset_password`).
5. **Block C2 and payload hashes**: propose `block_indicator` (`indicator_type: "sha256" | "ip" | "domain"`, `value`, `title`) — `Catalog` submits `BlockAndRemediate` automatically for file hashes and `Block` for network indicators.
6. **Recovery**: after re-imaging or verified eradication and `run_av_scan` (`Full`), propose `release_device` and `unrestrict_app_execution` via human approval.

---

## Case 4: Illicit OAuth app consent and service principal abuse

- **Playbook**: `oauth-app-consent-abuse` (`playbooks/oauth-app-consent-abuse.md`, priority 15)
- **KQL template**: `templates/kql/oauth-app-consent-abuse.kql`
- **Sample fixture**: `templates/incidents/oauth-app-consent.json`

### Steps

1. **Inspect the application**: call `lookup_entity { "kind": "oauth_app", "value": "<appId-or-sp-objectId>" }` to see `verifiedPublisher`, `accountEnabled`, reply URLs, delegated `oauth_grants` (e.g. `Mail.Read`, `Files.ReadWrite.All`, `offline_access`) and `app_role_assignments`.
2. **Audit who consented and what was accessed** (`run_sentinel_query`):
   - Query `AuditLogs` for `"Consent to application"` and `"Add OAuth2PermissionGrant"`.
   - Query `AADServicePrincipalSignInLogs` and `OfficeActivity` (`MailItemsAccessed` / `AppId`) to measure data exfiltration.
3. **Propose containment** (`request_action`):
   - `disable_service_principal` (`service_principal_id`: Entra service principal object ID GUID) — immediately stops token issuance for the malicious enterprise app.
   - `revoke_sessions` for the consenting user(s).
   - `block_indicator` for the app's reply URL domain / callback IP if attacker-hosted.
4. **Eradicate**: revoke the OAuth2 permission grants in Entra ID and delete the enterprise application once forensics are complete.

---

## Case 5: Password spray and MFA fatigue

- **Playbook**: `password-spray-mfa-fatigue` (`playbooks/password-spray-mfa-fatigue.md`, priority 35)
- **KQL template**: `templates/kql/identity-aitm-token-theft.kql`

### Steps

1. **Separate failed noise from accepted logins** (`run_sentinel_query` on `SigninLogs`): count distinct targeted accounts per source IP / user agent, then filter for `ResultType == 0` or `MfaDetail` approvals after repeated `500121` / `50074` denials.
2. **Check affected users**: call `lookup_entity { "kind": "user", "value": "<upn>" }` for every user who succeeded or accepted an MFA prompt.
3. **Propose targeted containment**:
   - For confirmed compromised accounts: `confirm_user_compromised`, `revoke_sessions`, `reset_password`.
   - For attacker infrastructure (excluding shared corporate/VPN NATs): `block_indicator` (`indicator_type: "ip"`).
   - Do **not** disable unaffected spray targets; post a `finding` summarising clean targets so approvers see the exact boundary.

---

## Case 6: Azure / Defender for Cloud privilege escalation and Key Vault enumeration

- **Playbook**: `azure-privilege-escalation` (`playbooks/azure-privilege-escalation.md`, priority 25)
- **KQL template**: `templates/kql/cloud-azure-privesc.kql`
- **Sample fixture**: `templates/incidents/azure-keyvault-privesc.json`

### Steps

1. **Pivot on caller identity** (`run_sentinel_query` on `AzureActivity`, `AzureDiagnostics` for `KeyVault`, and `AuditLogs`): list role assignments (`Microsoft.Authorization/roleAssignments/write`), Key Vault secret/key `SecretGet`/`SecretList` calls, and new federated credentials or secrets added to app registrations.
2. **Inspect caller**: call `lookup_entity` (`kind: "user"` or `kind: "service_principal"`) to verify whether the identity holds Owner, User Access Administrator, Privileged Role Administrator or high-impact Graph permissions.
3. **Check correlation with Defender for Endpoint**: if the caller is a human admin, check `SigninLogs` and `DeviceLogonEvents` to determine whether their workstation or token was stolen.
4. **Propose containment**:
   - If a workload identity / service principal was abused: `disable_service_principal`.
   - If a human identity was abused (and not in `protected_users`): `confirm_user_compromised`, `revoke_sessions`, `disable_user`.
   - If a compromised admin workstation is implicated: `isolate_device` and `collect_investigation_package`.
5. **Escalate break-glass or protected accounts**: if policy rejects containment because the caller is in `protected_users`, post a high-priority `question` `@mention`ing an on-call human lead so they execute out-of-band break-glass rotation.

---

## Case 7: Microsoft Purview DLP & Insider Risk data exfiltration

- **Playbook**: `data-exfiltration-cloud` (`playbooks/data-exfiltration-cloud.md`, priority 30)
- **KQL template**: `templates/kql/purview-dlp-insider-ai.kql`
- **Sample fixture**: `templates/incidents/purview-dlp-insider-exfil.json`

Follow **12 Sentinel MCP, Microsoft Purview and Defender Unified SOC** to inspect Purview DLP and Insider Risk alerts (`lookup_purview_context`), correlate `CloudAppEvents`, `OfficeActivity` and Defender `blobEvidence`/`teamsMessageEvidence`, and propose `revoke_sessions`, `disable_user` or `disable_service_principal` through human approval.

## What blueboard checks

- Incident-scoped actions (`update_incident`, `add_incident_comment`) must pass `incident_id`; entity-targeted actions should pass `incident` on `request_action` so `PolicyEngine` verifies targets appear in the linked incident's alerts/evidence.
- Protected users (break-glass, Global Admins), protected devices (DCs, hypervisors, PKI), protected apps (`protected_apps`) and protected indicators (corporate domains, Microsoft endpoints) are always rejected outright.
- Every KQL query executed during these cases is audited under `enrich.hunt` or `enrich.sentinel_hunt`.

## What is recorded in `audit_log`

- `incident.synced` / `playbook.attached`
- `enrich.lookup`, `enrich.purview`, `enrich.hunt`, `enrich.sentinel_hunt`
- `action.requested`, `action.approved_once`, `action.approved`, `action.succeeded` (or `action.dry_run`)

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `confirm_user_compromised` or `disable_service_principal` rejects UPN or display name | Graph Identity Protection and Service Principal endpoints require the Entra object ID GUID | Call `lookup_entity` first to read the exact `id` GUID and pass that GUID in `params`. |
| Policy flags *"target not in incident evidence"* on a lateral-movement host | The secondary host was discovered via KQL, not yet linked as an alert in Defender | Either link/sync the updated Defender incident (`sync_incident`) or proceed with explicit human approval and cite the KQL finding in `justification`. |
| Playbook did not auto-attach | A higher-priority playbook matched first, or alert title/categories differed | Call `attach_playbook` (`POST /api/incidents/{id}/playbook`) on an incident that does not yet have a playbook attached. |

## Related guides

- **04 Response playbooks and progressive checklists**, for playbook priority and custom authoring.
- **05 Entity lookups, Defender hunting and Sentinel KQL**, for query syntax and rate limits.
- **06 Requesting, previewing and approving containment**, for the full 21-action catalogue and approval rules.
- **12 Sentinel MCP, Microsoft Purview and Defender Unified SOC**, for Purview DLP/IRM, Sentinel MCP and Defender XDR ISOC walkthroughs.
