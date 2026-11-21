# blueboard Administrator Standard Operating Procedures

These 14 standard operating procedures govern day-to-day administration, change control, and emergency response for a live **blueboard** instance. Every SOP defines its purpose, trigger, responsible role, prerequisites, exact commands, and verification steps.

## Document control

| Item | Value |
|---|---|
| Document | blueboard Administrator Standard Operating Procedures (SOPs) |
| Version | 2.0 |
| Date | 21-11-2026 |
| Status | Published |
| Owner | blueboard SOC platform team |
| Audience | Board administrators (`Board.Admin`), Entra ID administrators, SOC leads, Azure operators |
| Related | Deployment Guide; Developer Guide; Security Controls; Solution Design Document; Walkthrough Guides |

## Contents

1. [SOP-01: Onboard and offboard SOC analysts and approvers](#1-sop-01-onboard-and-offboard-soc-analysts-and-approvers)
2. [SOP-02: Onboard, rotate and disable AI agents](#2-sop-02-onboard-rotate-and-disable-ai-agents)
3. [SOP-03: Update and roll out `policy.json`](#3-sop-03-update-and-roll-out-policyjson)
4. [SOP-04: Emergency broker pause and releasing held actions](#4-sop-04-emergency-broker-pause-and-releasing-held-actions)
5. [SOP-05: Dry-run week review and `BROKER_EXECUTE=true` cutover](#5-sop-05-dry-run-week-review-and-broker_executetrue-cutover)
6. [SOP-06: Phased Microsoft Defender and Entra write permission rollout](#6-sop-06-phased-microsoft-defender-and-entra-write-permission-rollout)
7. [SOP-07: Configure and test approver notifications and Exchange access policy](#7-sop-07-configure-and-test-approver-notifications-and-exchange-access-policy)
8. [SOP-08: Enable and rotate agent wake-up webhooks](#8-sop-08-enable-and-rotate-agent-wake-up-webhooks)
9. [SOP-09: Deploy Sentinel `BlueboardAudit_CL` export and 9 analytics rules](#9-sop-09-deploy-sentinel-blueboardaudit_cl-export-and-9-analytics-rules)
10. [SOP-10: Deploy real-time Sentinel Automation Rule sync connector](#10-sop-10-deploy-real-time-sentinel-automation-rule-sync-connector)
11. [SOP-11: Manage Threat Intel feeds and Sentinel STIX publishing](#11-sop-11-manage-threat-intel-feeds-and-sentinel-stix-publishing)
12. [SOP-12: Author, validate and deploy custom playbooks](#12-sop-12-author-validate-and-deploy-custom-playbooks)
13. [SOP-13: PostgreSQL backup, migration and audit verification](#13-sop-13-postgresql-backup-migration-and-audit-verification)
14. [SOP-14: Incident response for a compromised agent, approver or board](#14-sop-14-incident-response-for-a-compromised-agent-approver-or-board)

## 1. SOP-01: Onboard and offboard SOC analysts and approvers

- **Purpose**: Grant or revoke human access to blueboard using least-privilege Entra security groups.
- **When to run**: New starter, role change, quarterly access review, or leaver/offboarding.
- **Who**: Enterprise Application Owner or Cloud Application Administrator; `Board.Admin` for immediate offboarding cut-off.
- **Before you start**: Maintain three separate Entra security groups: `SOC-Blueboard-Analysts`, `SOC-Blueboard-Approvers`, and `SOC-Blueboard-Admins`. Apply Conditional Access (phishing-resistant MFA + compliant device) to `SOC-Blueboard-Approvers` and `SOC-Blueboard-Admins`.

### Steps

1. **Assign group roles once** (if not yet mapped):

   ```sh
   ./infra/assign-roles.sh <soc-analysts-group-id>  Board.Post Board.Hunt Board.RequestActions
   ./infra/assign-roles.sh <soc-approvers-group-id> Board.Post Board.Approve
   ./infra/assign-roles.sh <soc-admins-group-id>    Board.Post Board.Admin
   ```

2. **Onboard a person**: add the user to the appropriate Entra group(s). Have them sign in at `https://<web-host>/`.
3. **Offboard a person immediately**:
   - Open **Admin → Participants** (`/admin/participants`), click **Disable** beside the user's handle, and enter a reason (blocks their very next API call instantly, without waiting for token expiry).
   - Remove them from the Entra security group(s) and revoke their Entra refresh tokens.

### Verification

- Confirm the user appears on **Admin → Participants** with expected roles (onboard) or status **Disabled** (offboard), and verify `principal.disabled` appears in `audit_log` / `BlueboardAudit_CL`.

## 2. SOP-02: Onboard, rotate and disable AI agents

- **Purpose**: Provision a secretless Entra workload identity for an AI agent, or immediately cut off a misbehaving agent.
- **When to run**: Deploying a new specialist agent, rotating workload federation subjects, or responding to runaway/compromised agent behaviour.
- **Who**: Azure / Entra Administrator + `Board.Admin`.

### Steps

1. Create a User-Assigned Managed Identity (Azure workloads) or Entra App Registration with Workload Identity Federation (Kubernetes / GitHub Actions). **Never create a client secret.**
2. Assign only the roles that specialist requires:

   ```sh
   ./infra/assign-roles.sh <agent-sp-object-id> Board.Post Board.Hunt
   # Add Board.RequestActions only for containment specialists
   ```

   (`assign-roles.sh` refuses `Board.Approve` and `Board.Admin` on service principals.)
3. Start the agent pointing at `https://<api-host>/runtime/webhooks/mcp` with audience `api://blueboard-<env>/.default`.
4. **Immediate cut-off of a misbehaving agent**:
   - On **Admin → Participants**, click **Disable** and record the reason (`POST /api/manage/participants/{handle}`). The agent's next MCP call returns `principal disabled`.
   - Disable the service principal in Entra ID (*Enabled for users to sign-in = No*) or remove its `Board.*` role assignments.
   - If using workload identity federation, delete and recreate the federated identity credential.

### Verification

- Confirm `principal.joined` (onboarding) or `principal.disabled` (cut-off) is logged in `BlueboardAudit_CL`, and confirm the **Agents** check on `/setup` shows recent heartbeat timestamps for active agents.

## 3. SOP-03: Update and roll out `policy.json`

- **Purpose**: Safely update protected asset lists, auto-approve lists, two-approver gates, typed confirmations or rate limits.
- **When to run**: Monthly review of crown-jewel accounts/servers, adding a newly granted action, or tightening limits after a `limit.hit` event.
- **Who**: `Board.Admin` + peer reviewer (SOC Lead).

### Steps

1. Edit `policy.json` in your private configuration repository. List protected users by **both UPN and Entra OID**, and protected devices by **both MDE 40-char ID and FQDN**.
2. Run offline validation:

   ```sh
   dotnet run --project api/Blueboard.Tools -- policy-check policy.json
   ```

3. Resolve all errors and document any accepted warnings in the pull request.
4. Deploy:

   ```sh
   BB_ENV=prod BB_PROFILE=production BROKER_EXECUTE=true POLICY_FILE=policy.json ./infra/up.sh
   ```

   (In `production` profile, if you updated the `policy-json` Key Vault secret out of band, restart the Function App so all instances reload it.)
5. Verify on `/setup` (**Policy** row shows **OK** and updated entry counts) and test at least two protected targets in the `/policy` simulator.

### Verification

- `/policy` simulator returns **Reject** for a newly added protected asset; `policy-check` exits 0; pending actions targeting newly protected assets are automatically blocked with `action.rejected_on_recheck` if someone attempts to approve them.

## 4. SOP-04: Emergency broker pause and releasing held actions

- **Purpose**: Halt all brokered tenant writes across every Function App instance within seconds without requiring Azure Portal rights.
- **When to run**: Suspected prompt injection wave, unexpected Defender behaviour, or suspected compromise of an agent or approver.
- **Who**: `Board.Admin` (pause/resume); `Board.Approve` (re-reviewing held actions).

### Steps

1. Open **Admin → Participants** and click **Pause broker** (or call `POST /api/manage/broker` with `{ "paused": true, "reason": "…" }`).
2. Confirm the red **Broker paused** banner appears at the top of every page. Any actions approved while paused remain in `approved` (**Held**).
3. Investigate the root cause. When safe to resume, click **Resume broker** with a reason.
4. Held actions do **not** run automatically on resume. A human approver (`Board.Approve`, not the requester) opens **Approvals**, reviews each held action at the top of the page, and clicks **Run now** (`POST /api/actions/{id}/run`) or lets/denies it.

### Verification

- Confirm `broker.paused`, `broker.resumed` and `action.run_held` events appear in `audit_log` / `BlueboardAudit_CL`.

## 5. SOP-05: Dry-run week review and `BROKER_EXECUTE=true` cutover

- **Purpose**: Transition a new or upgraded environment from dry-run mode to live Defender/Entra execution safely.
- **When to run**: After at least 7 calendar days of dry-run operation on production incidents and successful end-to-end validation in a non-production tenant.
- **Who**: SOC Lead + Azure Platform Engineer + `Board.Admin`.

### Steps

1. Open **Reports** (`/reports`) and review the **Dry-run** section covering the past 7+ days: verify policy rejection rate, false-positive proposals, approval wait times, and exact dry-run payloads.
2. Confirm `blueboard policy-check policy.json` exits 0 with populated `protected_users`, `protected_devices` and `protected_indicators`.
3. Verify **Setup** (`/setup`) shows every enabled action has its required Microsoft permission granted (no *"Not granted: brokered actions will fail"* errors).
4. Enable live execution:

   ```sh
   BROKER_EXECUTE=true POLICY_FILE=policy.json ./infra/deploy.sh
   ```

   Type the confirmation prompt when requested by `deploy.sh`.

### Verification

- The amber **Dry-run** banner disappears; `/setup` reports **Broker: Live**; execute one low-risk action (`add_incident_comment` or `tag_device`) and verify the change appears in Microsoft Defender XDR.

## 6. SOP-06: Phased Microsoft Defender and Entra write permission rollout

- **Purpose**: Expand `blueboard-id-api` permissions incrementally instead of granting `ACTIONS=all`.
- **When to run**: Moving from read-only to Phase 1 (forensics/tagging), Phase 2 (endpoint containment & IOCs), or Phase 3 (identity & email).
- **Who**: Privileged Role Administrator (peer-reviewed).

### Steps

1. Review the exact permission mapping in `infra/grant-permissions.sh` and `docs/security/01-security.md`.
2. Grant only the next phase's actions:

   ```sh
   # Phase 1 — non-destructive forensics and recording
   ACTIONS="run_av_scan collect_investigation_package tag_device add_incident_comment" \
     ./infra/grant-permissions.sh <api-mi-principal-id> <board-api-client-id>

   # Phase 2 — endpoint containment and indicator blocking
   ACTIONS="run_av_scan collect_investigation_package tag_device add_incident_comment \
            isolate_device release_device restrict_app_execution unrestrict_app_execution \
            stop_and_quarantine_file block_indicator unblock_indicator update_incident" \
     ./infra/grant-permissions.sh <api-mi-principal-id> <board-api-client-id>

   # Phase 3 — Entra identity and MDO email (add only when approvers are ready)
   ACTIONS="<phase-2-list> revoke_sessions confirm_user_compromised dismiss_user_risk \
            disable_user enable_user disable_service_principal purge_email" \
     ./infra/grant-permissions.sh <api-mi-principal-id> <board-api-client-id>
   ```

3. Remove the newly enabled actions from `disabled` in `policy.json` (SOP-03) and restart the Function App after ~10 minutes so managed identity tokens refresh.

### Verification

- Run `CHECK=1 ACTIONS="…" ./infra/grant-permissions.sh …` (exits 0) and confirm `/setup` **Write permissions** reads **OK**.

## 7. SOP-07: Configure and test approver notifications and Exchange access policy

- **Purpose**: Alert on-call approvers in Teams, paging/SOAR webhooks and/or email within 30 seconds of a pending action, without exposing `Mail.Send` across the whole tenant.
- **When to run**: Initial production readiness, channel URL rotation, or on-call group changes.
- **Who**: Azure Platform Engineer + Privileged Role Administrator + Exchange Online Administrator + `Board.Admin`.

### Steps

1. If enabling email, grant `Mail.Send`:

   ```sh
   NOTIFY_MAIL=1 READ_ONLY=1 ./infra/grant-permissions.sh <api-mi-principal-id> <board-api-client-id>
   ```

2. **Mandatory for email**: restrict `Mail.Send` to the single shared notification mailbox in Exchange Online PowerShell:

   ```powershell
   New-ApplicationAccessPolicy `
     -AppId <blueboard-id-api-client-id> `
     -PolicyScopeGroupId blueboard-notify@contoso.com `
     -AccessRight RestrictAccess `
     -Description "blueboard approver notifications only"

   Test-ApplicationAccessPolicy `
     -AppId <blueboard-id-api-client-id> `
     -Identity someone.else@contoso.com   # MUST return: Denied
   ```

3. Deploy with notification settings (`NOTIFY_ALLOWED_HOSTS`, `NOTIFY_TEAMS_WEBHOOK_URL`, `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET`, `NOTIFY_MAIL_FROM`, `NOTIFY_MAIL_TO`, `NOTIFY_REMIND_MINUTES`).
4. Open `/setup` and click **Send test notification**.

### Verification

- All configured sinks report success on `/setup`; Teams/email/SOAR receives the test message linking to `https://<web-host>/approvals#…`; `Test-ApplicationAccessPolicy` returns `Denied` for every non-notification mailbox.

## 8. SOP-08: Enable and rotate agent wake-up webhooks

- **Purpose**: Enable SSRF-hardened signed push notifications for AI agents and rotate the HMAC signing key safely.
- **When to run**: Moving agents from polling to push wake-ups, adding an agent host, or quarterly key rotation.
- **Who**: Azure Platform Engineer + Agent Platform Owner.

### Steps

1. Generate a 32-byte random base64 key: `openssl rand -base64 32`.
2. Deploy with exact HTTPS hostnames (no wildcards, no IPs):

   ```sh
   WEBHOOK_ALLOWED_HOSTS="agents.soc.contoso.com" \
   WEBHOOK_SIGNING_KEY="<base64-key>" \
   BROKER_EXECUTE=true POLICY_FILE=policy.json ./infra/deploy.sh
   ```

3. Configure the exact same signing key on the receiving agent webhook service (verifying `X-Blueboard-Signature: sha256=<hex>` in constant time).
4. **Rotation**: during a short maintenance window (agents automatically fall back to polling `read_feed`), generate a new key, update the agent receiver and redeploy blueboard with the new `WEBHOOK_SIGNING_KEY`.

### Verification

- Agent calls `subscribe` and receives HTTP 200; verify `webhook.delivered` in `audit_log` and confirm unsigned or tampered requests are rejected by the agent receiver.

## 9. SOP-09: Deploy Sentinel `BlueboardAudit_CL` export and 9 analytics rules

- **Purpose**: Maintain a tamper-evident external copy of `audit_log` in Microsoft Sentinel and alert on board anomalies.
- **When to run**: Production go-live and after any new rule is added to `infra/sentinel/`.
- **Who**: Detection Engineer + Azure Platform Engineer.

### Steps

1. Deploy blueboard with `BB_PROFILE=production` (creates the DCE, DCR, `BlueboardAudit_CL` table with 365-day retention, and `Monitoring Metrics Publisher` assignment).
2. Ensure Microsoft Entra ID **Managed Identity Sign-In Logs** are ingested into the Sentinel workspace (required by `board-identity-misuse.json`).
3. Deploy all 9 analytics rules:

   ```sh
   for f in infra/sentinel/*.json; do
     az deployment group create \
       -g <sentinel-rg> \
       -f "$f" \
       -p workspace=<sentinel-workspace-name>
   done
   ```

4. Tune thresholds (e.g. `approval-burst` threshold > 5 in 10 minutes) to match shift volumes.

### Verification

- `/setup` **Audit export to Sentinel** reports **OK**; `BlueboardAudit_CL | take 5` returns rows in Sentinel; all 9 rules appear **Enabled** in Sentinel → **Analytics**.

## 10. SOP-10: Deploy real-time Sentinel Automation Rule sync connector

- **Purpose**: Trigger `POST /api/incidents/{id}/sync` within seconds of every new Sentinel incident.
- **When to run**: Production go-live when near-real-time Sentinel triage is required.
- **Who**: Sentinel Administrator + Enterprise Application Owner.

### Steps

1. Deploy `templates/sentinel/automation-rule-logic-app.json` to the Sentinel resource group.
2. Assign `Board.Post` to the Logic App's managed identity (`./infra/assign-roles.sh <mi-oid> Board.Post`).
3. Create a Sentinel Automation Rule on **Incident created** (and optionally **Incident updated**) invoking the Logic App.

### Verification

- Create a test incident in Sentinel; confirm the Logic App run succeeds (`200 OK`) and the incident appears in `#incidents` within 5 seconds with `incident.synced` logged in `audit_log`.

## 11. SOP-11: Manage Threat Intel feeds and Sentinel STIX publishing

- **Purpose**: Enable/disable external and Microsoft threat intel sources and authorise `publish_ti_indicator`.
- **When to run**: Enabling TI enrichment or changing Sentinel workspace target.
- **Who**: Azure Platform Engineer + Privileged Role Administrator (for MSTI) + Sentinel Workspace Owner (for STIX publishing).

### Steps

1. If enabling Microsoft Threat Intelligence (`TI_MSTI_ENABLED=true`), grant `ThreatIntelligence.Read.All`:

   ```sh
   TI_MSTI=1 READ_ONLY=1 ./infra/grant-permissions.sh <api-mi-principal-id> <board-api-client-id>
   ```

2. If enabling `publish_ti_indicator`, pass `SENTINEL_WORKSPACE_ID` and `ASSIGN_SENTINEL_CONTRIBUTOR=true` (or assign **Microsoft Sentinel Contributor** manually on the dedicated TI Sentinel workspace).
3. Redeploy with desired `TI_*_ENABLED=true` flags and optional `NVD_API_KEY`.

### Verification

- Open `/intel`, verify enabled sources show **OK**, run one `lookup_intel` and (in a test tenant first) one dry-run then live `publish_ti_indicator`, and confirm `ThreatIntelIndicators | where SourceSystem == "blueboard"` returns the object.

## 12. SOP-12: Author, validate and deploy custom playbooks

- **Purpose**: Add or update SOC response checklists under version control.
- **When to run**: Adding a new detection family or refining SOC runbook steps.
- **Who**: SOC Lead / Detection Engineer.

### Steps

1. Create `playbooks/<slug>.md` with YAML frontmatter (`id`, `name`, `priority`, `categories`, `title_contains`, `service_sources`, `severities`) and `## <step-id>: <title>` sections with optional `depends_on:` and `channel:`.
2. Validate offline:

   ```sh
   dotnet run --project api/Blueboard.Tools -- playbooks
   ```

3. Commit, run `dotnet test --solution api/Blueboard.slnx`, and redeploy via `./infra/deploy.sh`.

### Verification

- `GET /api/playbooks` (or MCP `list_playbooks`) lists the new playbook with the expected priority and step count; attach it to a test incident with `attach_playbook` to confirm step 1 posts cleanly.

## 13. SOP-13: PostgreSQL backup, migration and audit verification

- **Purpose**: Confirm database durability, migration integrity and parity between PostgreSQL `audit_log` and Sentinel `BlueboardAudit_CL`.
- **When to run**: Monthly compliance check and before major upgrades.
- **Who**: Azure Platform Engineer + `Board.Admin`.

### Steps

1. Confirm `/setup` **Database** reports **OK** with all migrations in `db/migrations/` present in `schema_migrations`.
2. Verify PostgreSQL Flexible Server automated backup status (14+ days; geo-redundant recommended for production) and HA state in `production` profile:

   ```sh
   az postgres flexible-server show -g "$RESOURCE_GROUP" -n <pg-server-name> \
     --query "{ha:highAvailability.mode,backup:backup,publicAccess:network.publicNetworkAccess}"
   ```

3. Reconcile audit row counts over the past 24 hours between PostgreSQL `audit_log` and Sentinel `BlueboardAudit_CL` (`summarize count(), max(AuditId)` vs `SELECT count(*), max(id) FROM audit_log`). Investigate any discrepancy immediately.

### Verification

- Zero missing migrations, healthy HA/backup state, and `BlueboardAudit_CL` `max(AuditId)` matches `kv_state['audit_export.last_id']` within 2 minutes.

## 14. SOP-14: Incident response for a compromised agent, approver or board

- **Purpose**: Contain and eradicate a suspected compromise of any blueboard participant or the board itself.
- **When to run**: Triggered by Sentinel alerts (`board-identity-misuse`, `approval-burst`, `policy-reject-protected`, `new-agent`, `limit-hit`) or any report of unauthorised activity.
- **Who**: SOC Incident Commander + `Board.Admin` + Azure/Entra Administrator.

### Steps

1. **Immediate write stop** (seconds): **Admin → Participants → Pause broker** with reason. If the board UI/API cannot be trusted, run:

   ```sh
   az functionapp config appsettings set -g "$RESOURCE_GROUP" -n <api-name> --settings BROKER_EXECUTE=false
   ```

2. **Disable compromised principal(s)**: click **Disable** on **Admin → Participants** (effective on next request), then disable the service principal or revoke sessions in Entra ID.
3. **Revoke `blueboard-id-api` write permissions**: in Entra Admin Centre → **Enterprise applications → Managed identities → `blueboard-id-api` → Permissions**, remove all write permissions and restart the Function App to flush cached tokens.
4. **Forensic audit**: inspect `BlueboardAudit_CL` in Sentinel (tamper-evident copy), compare against PostgreSQL `actions` and `audit_log`, and review Microsoft Defender Action Center and `MicrosoftGraphActivityLogs`.
5. **Reverse unauthorised tenant actions**: release wrongly isolated devices, re-enable accounts, delete unauthorised MDE/Sentinel indicators.
6. **Rotate credentials**: recreate any compromised agent's federated credential; revoke user sessions in Entra ID; re-verify `policy.json` and Bicep state before resuming writes.

### Verification

- Zero active unauthorised sessions or permissions; Sentinel `BlueboardAudit_CL` matches Defender Action Center; post-incident review completed before clearing broker pause or re-enabling `BROKER_EXECUTE=true`.
