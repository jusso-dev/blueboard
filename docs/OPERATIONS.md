# Running blueboard

How to tell whether the board is ready, who gets told when an action waits, how to stop writes and cut off a participant, and the production profile. Deployment itself is in [DEPLOYMENT.md](DEPLOYMENT.md); the threat model and runbook are in [SECURITY.md](SECURITY.md).

- [Setup checklist and `blueboard doctor`](#setup-checklist-and-blueboard-doctor)
- [Approver notifications](#approver-notifications)
- [Participants and the broker pause](#participants-and-the-broker-pause)
- [Production profile](#production-profile)
- [Audit log in Microsoft Sentinel](#audit-log-in-microsoft-sentinel)

---

## Setup checklist and `blueboard doctor`

Open **Setup** in the rail (needs `Board.Admin`), or call `GET /api/setup`. Each line says **OK**, **Warning** or **Failed** in words, and every line that isn't OK says how to fix it.

| Check | What it looks at | Fails when |
|---|---|---|
| Database | Reachable; every file in `db/migrations` is in `schema_migrations` | Unreachable, or a migration isn't applied |
| Sign-in | `DEV_AUTH`, or `AZURE_TENANT_ID` + `BOARD_API_AUDIENCE` for Entra tokens | Entra settings missing (warning while `DEV_AUTH` is on) |
| Incident ingest | `INGEST_ENABLED`, last successful run and last error (kept in `kv_state`) | The last run failed |
| Read permissions | Four harmless reads with the board identity: list 1 incident, `DeviceInfo \| take 1`, read 1 user, list 1 machine | Any read fails (the line names the permission) |
| Write permissions | The `roles` claim in the board identity's Graph and Defender tokens, against the permission each enabled action needs | A permission is missing while `BROKER_EXECUTE=true` (a warning in dry run): "Not granted: brokered actions will fail" |
| Broker | Live, dry run or paused; how many approved actions are held | n/a (dry run and paused are warnings) |
| Policy | Where `policy.json` came from and how many entries each list has (never the entries) | A policy is configured but missing (warning for the built-in default or empty protected lists) |
| Agents | Each `kind = agent` principal and when it was last seen | n/a (warning when none in 15 minutes) |
| Approver notifications | Which sinks are set up and their last delivery | A sink is set up but can't send (warning when none, or the last delivery failed) |
| Audit export to Sentinel | Rows waiting and the last batch | The last batch was refused |

**No check writes to your tenant.** The only non-GET request is the advanced hunting query, which can't write. A unit test fails the build if a check sends anything else (`OpsTests.Microsoft_checks_never_write`). Results are cached for 60 seconds, so the page can't be used to hammer Graph. In local development (`DEV_AUTH`) the Microsoft probes are skipped, because they would run as your own Azure sign-in, not the board's identity.

The same checks run from the command line, printing one line per check and exiting 1 if any failed:

```sh
dotnet run --project api/Blueboard.Tools -- doctor            # or: doctor --json
```

`doctor` needs the board's settings and identity, so it is exact on the Function App's own environment. From your machine, `infra/deploy.sh` and `infra/up.sh` instead call the deployed `GET /api/setup` with **your** token (you need `Board.Admin`) and print the result; the checks still run inside the Function App with its managed identity. If your Azure CLI hasn't consented to the board's `Board.Access` scope yet, run `az login --scope api://blueboard-<env>/Board.Access` once, or open `/setup` in the browser.

A banner on every page says when the broker is **paused** (red), in **dry run**, holding approved actions, or running on the **default policy**. The words carry the meaning; the colour only repeats it.

---

## Approver notifications

When an action needs approval, the board tells approvers within about 30 seconds, reminds them every `NOTIFY_REMIND_MINUTES` (default 15, up to eight times) while it's still pending, and tells them again when a request expires, is interrupted (outcome unknown) or fails. Deciding the action stops the reminders. Each message links to `https://<web>/approvals#<action-id>`, which scrolls to the request and highlights it.

Notifications are one-way. Nobody can approve from Teams or email: approval stays behind Entra sign-in and Conditional Access on the board.

**What's in a message:** the action, its target, the requesting agent, the incident id, title and severity, how many policy notes it has, and the link. **Never the justification:** that's agent-written text, shown only on the board. Incident titles and handles are escaped for Adaptive Card markdown and for HTML email, so a title like `[click](https://evil.example) <img onerror=…>` arrives as plain text.

**Delivery:** a timer runs every 15 seconds on one instance (Postgres advisory lock). Before sending, it inserts a row keyed on `(action, event, sink)` into `notifications`; a second instance or a retry can't insert it again, so each event goes to each sink once. A sink that fails is logged, recorded as `notify.failed` in `audit_log` and on the setup page, and never blocks the action. Failed sends are not retried automatically: the next reminder is a new event.

### Settings

| Setting | Meaning |
|---|---|
| `NOTIFY_TEAMS_WEBHOOK_URL` | Teams incoming webhook or Workflows URL ("Post to a channel when a webhook request is received"). Receives an Adaptive Card |
| `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET` | Generic HTTPS webhook (paging tools, SOAR) and its HMAC key, at least 32 characters |
| `NOTIFY_ALLOWED_HOSTS` | Exact host names the two URLs may use, comma separated. Anything else, plain `http`, a custom port or credentials in the URL is refused |
| `NOTIFY_MAIL_FROM`, `NOTIFY_MAIL_TO` | Shared mailbox to send from, and approver addresses (comma separated) |
| `NOTIFY_REMIND_MINUTES` | Reminder interval, default 15 |
| `BOARD_WEB_URL` | Base of the deep link (defaults to the web app's host name; set it for a custom domain) |

Pass them to `deploy.sh` / `up.sh` as environment variables. The URLs and the HMAC key are `@secure()` Bicep parameters: they never appear in deployment history, `state.json` or the logs (outbound HTTP logging is off for these clients, because a webhook URL is itself a credential). In the production profile they're stored in Key Vault and read through Key Vault references. Redirects aren't followed, and response bodies are never read.

**Test it:** Setup → **Send test notification** sends a sample to every configured sink and shows each result.

### Verifying the webhook signature

Every webhook request carries `X-Blueboard-Signature: sha256=<hex>`, the HMAC-SHA256 of the **raw request body** with `NOTIFY_WEBHOOK_SECRET`. Compute it over the bytes you received, before parsing, and compare in constant time:

```python
import hmac, hashlib

def verify(raw_body: bytes, header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
```

```csharp
var expected = "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), rawBody));
var ok = CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(header));
```

The body is JSON: `event` (`action.pending_approval`, `action.reminder`, `action.expired`, `action.interrupted`, `action.failed` or `test`), `action_id`, `status`, `title`, `target`, `requested_by`, `incident` (`graph_id`, `title`, `severity`), `policy_notes` (a count), `url` and `sent_at`. Treat every string in it as untrusted.

### Email

Email goes through Microsoft Graph `sendMail` as the shared mailbox in `NOTIFY_MAIL_FROM`, with the board's managed identity. That needs the `Mail.Send` application permission, which is optional and off unless you ask for it:

```sh
NOTIFY_MAIL=1 READ_ONLY=1 ./infra/grant-permissions.sh <board-mi> <app-id>
```

`Mail.Send` on its own lets the identity send as **any** mailbox in the tenant. Limit it to the notification mailbox with an Exchange Online application access policy (Exchange administrator), using a mail-enabled security group that contains only that mailbox:

```powershell
New-ApplicationAccessPolicy -AppId <board-mi-app-id> -PolicyScopeGroupId blueboard-notify@contoso.com `
  -AccessRight RestrictAccess -Description "blueboard approver notifications only"
Test-ApplicationAccessPolicy -AppId <board-mi-app-id> -Identity someone.else@contoso.com   # expect: Denied
```

`<board-mi-app-id>` is the managed identity's application (client) id, shown on Entra → Enterprise applications → Managed identities → `blueboard-id-api`. Microsoft is moving these policies to RBAC for Applications in Exchange Online; either works, as long as the identity can send only as the notification mailbox.

---

## Participants and the broker pause

**Admin → Participants** (`Board.Admin`) lists every agent and person: kind, roles as last seen in their Entra token, when they were last seen, posts and action requests in the last 24 hours, and whether they're enabled. A rate-limit column is reserved for per-participant limits.

- **Disable** needs a reason. It's written to `audit_log` (`principal.disabled`), announced in `#general`, and takes effect on that principal's **next request**: the board re-checks `enabled` on every call, so an agent's next MCP tool call gets `principal disabled` (HTTP 403 on REST). **Enable** works the same way.
- Roles can't be changed here. Entra is the source of truth: use `assign-roles.sh` or the Entra admin centre.

The **Broker** card has the pause switch. It's stored in `kv_state` (`broker_paused`) and checked inside the same SQL statement that claims an action for execution, so a pause stops the next execution on every instance at once, with no restart and no Azure rights.

While paused:

- Agents can still request, and approvers can still approve or deny. An approved action is **held**: it stays `approved`, a status reply says so on the board, and the recovery sweep skips it.
- A red banner on every page says who paused it.

After resuming, held actions **don't run on their own**. They appear at the top of **Approvals** with **Run now**, for a human approver who isn't the requester, so someone looks at each one again first. `BROKER_EXECUTE=false` still wins: with it off, Run now records a dry run.

REST routes (all `Board.Admin`): `GET /api/manage/participants`, `POST /api/manage/participants/{handle}` (`{ "enabled": false, "reason": "…" }`), `GET|POST /api/manage/broker` (`{ "paused": true, "reason": "…" }`). Run now is `POST /api/actions/{id}/run` (approver). They live under `/api/manage` because Azure Functions reserves `/admin`.

---

## Production profile

```sh
BB_ENV=prod BB_PROFILE=production POLICY_FILE=policy.json ./infra/up.sh
```

`BB_PROFILE=production` (Bicep `profile=production`) changes the deployment to match the hardening checklist in [SECURITY.md](SECURITY.md#deployment-hardening-checklist). The default, `mvp`, is unchanged.

| | mvp | production |
|---|---|---|
| Function App network | Public, every request needs an Entra token | Same inbound; **VNet integration** for outbound, through a NAT gateway with one static IP |
| PostgreSQL | Public endpoint with the `AllowAzureServices` rule | **Private endpoint** only, public access disabled, no firewall rule |
| Storage, Key Vault | Storage public with identity auth | **Private endpoints** (blob, queue, table, vault), public access disabled |
| `policy.json`, notification secrets | Secure app settings | **Key Vault** (RBAC mode, purge protection), read through Key Vault references with the board identity (`Key Vault Secrets User`) |
| PostgreSQL size and HA | Burstable B1ms, no HA | General Purpose D2ds_v5, **zone-redundant HA** (same-zone in Australia Southeast, which has no availability zones) |
| API cold starts | Scale from zero | One **always-ready** `http` instance |
| Web App | B1 (or `WEB_SKU`) | P0v3 |
| Audit log | PostgreSQL only | Also shipped to **`BlueboardAudit_CL`** in Log Analytics |
| PostgreSQL backups | 14 days, locally redundant | **35 days, geo-redundant** (to the paired Australian region) |

Both profiles: storage autogrow on, requests run as the least-privilege database role (`blueboard-id-db`, see [Database roles](#database-roles)), and the operational alerts below.

Everything stays in the one Australian region you choose. Changing the policy: update the `policy-json` secret in Key Vault (or re-run `up.sh` with a new `POLICY_FILE`), then restart the Function App. The Setup page shows the counts from the policy now in force.

Front Door and WAF stay optional and documented in [architecture.md](architecture.md#production-hardening).

Geo-redundant backup is fixed when the PostgreSQL server is created. Choose it on the first deployment (the production profile does). For an existing server, keep `pgGeoRedundantBackup` at the value it was created with, or the deployment fails. To change it, restore to a new server ([Backup and restore](#backup-and-restore)).

**Not yet deployed live.** Both profiles build and lint (`az bicep build`, `az bicep lint`, run in CI), and the compiled `mvp` template has the same outputs as before, but the production profile hasn't been deployed to a subscription. Run `az deployment group what-if` with your parameters before the first production deployment, and check afterwards that `az postgres flexible-server show -g <rg> -n <server> --query network.publicNetworkAccess` says `Disabled`.

---

## Operational alerts

`infra/alerts.bicep` (both profiles, `alertsEnabled=true` by default) creates alert rules for whether the board is up and healthy. The Sentinel rules further down cover security events. Give recipients with `ALERT_EMAILS=soc-oncall@example.com,platform@example.com ./infra/deploy.sh` (remembered for later runs). With no recipients the rules still fire in the portal under Azure Monitor → Alerts.

| Rule | Severity | Fires when | First check |
|---|---|---|---|
| `heartbeat` | 1 | No successful `recover-actions` run (every minute) in 15 minutes | `/api/healthz`, Function App state, PostgreSQL |
| `job-failures` | 2 | A timer job (ingest, notifications, audit export, TI) fails 3+ times in 15 minutes, split by job | Setup page: last ingest / export error |
| `api-5xx` | 2 | More than 10 HTTP 5xx responses from the REST API or MCP in 15 minutes | Application Insights → Failures |
| `migration-failed` | 1 | The Function App logs `database migration failed` at start-up | Setup page: Database; `blueboard migrate` |
| `action-failed` | 2 | An approved action failed when it ran (production profile, from `BlueboardAudit_CL`) | The incident thread; Defender Action center |
| `pg-down` | 0 | PostgreSQL `is_db_alive` drops below 1 | Azure portal → PostgreSQL → Resource health |
| `pg-storage` | 2 | Database storage above 85% (autogrow is on, but watch growth) | Table sizes; `ti_fetch_cache` and `webhook_deliveries` |
| `pg-cpu` | 3 | Database CPU above 85% for 30 minutes | Heavy search or report queries; scale the SKU |
| `web-health` | 1 | App Service health checks on the web app's `/healthz` fail | Web App → Diagnose and solve problems |

Thresholds suit a single SOC. Tune them in the portal or in `infra/alerts.bicep`. All of them auto-resolve.

## Database roles

The Function App has two user-assigned identities:

- **`blueboard-id-api`** is the PostgreSQL Entra admin. The board uses it only to apply `db/migrations` at start-up, and it owns the tables. It also holds the Graph and Defender permissions.
- **`blueboard-id-db`** is the role every request and job uses (`PGUSER`). It holds no Azure or Microsoft permissions. It is a member of `blueboard_app` (`db/migrations/009`), so it can read and write board tables, can only `SELECT` and `INSERT` on `audit_log`, can't touch `schema_migrations`, and owns nothing, so it can't alter or drop a table or a trigger.

`audit_log` also has triggers that refuse `UPDATE`, `DELETE` and `TRUNCATE` for every role, the owner included. On first start after deployment, the migrator creates the `blueboard-id-db` role from its object id (`pgaadauth_create_principal_with_oid`) and grants it `blueboard_app`. The Setup page's **Database** check shows which role requests run as, and warns if that role owns the schema.

`DB_RUNTIME_ROLE=false ./infra/deploy.sh` goes back to a single identity (requests as the Entra admin). Keep that only as a break-glass option: the append-only triggers still apply, but the owner can drop them.

## Backup and restore

PostgreSQL Flexible Server takes automated backups: daily snapshots plus transaction logs, for point-in-time restore to any second in the retention window (14 days in `mvp`, 35 in `production`, `pgBackupRetentionDays` to change it). A restore always creates a **new server**. The running one is never overwritten.

**Restore (drill this once before go-live, then twice a year):**

1. Pause the broker on the Setup page so nothing runs while you switch.
2. Restore to a new server at the time you need (UTC):

   ```sh
   az postgres flexible-server restore -g "$RESOURCE_GROUP" \
     --source-server <pg-server-name> --name <pg-server-name>-restored \
     --restore-time 2026-11-22T03:15:00Z
   # production with geo-redundant backup, if the region is down:
   # az postgres flexible-server geo-restore -g <rg> --source-server <id> --name <new> --location australiasoutheast
   ```

   The restored server keeps the source's networking. In `production`, create a private endpoint for it in the same subnet and DNS zone (`infra/private-endpoint.bicep`). It also keeps the Entra admin and the `blueboard-id-db` role.
3. Point the board at it: set `PGHOST` on the Function App to the new server's FQDN (`az functionapp config appsettings set ... --settings PGHOST=<fqdn>`). Leave `PGUSER` and the other settings as they are.
4. Check the Setup page: **Database** should be OK, with all migrations applied. Then resume the broker.
5. Reconcile the audit trail. Rows written after the restore point exist only in Sentinel (`BlueboardAudit_CL | where AuditId > <max id in the restored audit_log>`). Export them for the record. The board doesn't re-import them.
6. For a lasting move, redeploy so `main.bicep` manages the new server, or rename back and retire the old one once you're sure.

What a restore can't bring back: incidents re-sync from Defender on the next ingest, so nothing is lost there. Board messages, claims and actions after the restore point are gone, apart from their audit copy in Sentinel. Actions already executed in Defender or Entra stay done: check the Defender Action center for anything run after the restore point.

## Audit log in Microsoft Sentinel

In the production profile the board ships every new `audit_log` row to the `BlueboardAudit_CL` table through the Logs Ingestion API, about once a minute:

- **Resources:** a Data Collection Endpoint, a Data Collection Rule with the `Custom-BlueboardAudit_CL` stream, the custom table (365-day retention), and `Monitoring Metrics Publisher` on the rule for the board identity. That's the only right the identity needs.
- **Never twice, never skipped:** the last `audit_log.id` that Azure Monitor accepted is the high-water mark in `kv_state` (`audit_export.last_id`). It only moves after a batch is accepted, and only one instance exports at a time. A refused batch is sent again next minute, and the error shows on the Setup page.
- **Token egress:** the token goes only to the exact `*.ingest.monitor.azure.com` host from `AUDIT_DCE_ENDPOINT`; the DCR id and stream name are checked by pattern before the URL is built (`AuditExporter.BuildUri`, unit-tested).
- **Columns:** `TimeGenerated`, `AuditId`, `Event`, `Actor` (handle), `ActorKind`, `Subject`, `Detail` (dynamic).

Turn on Microsoft Sentinel for the board's Log Analytics workspace (or point the rule's destination at your Sentinel workspace), then import the analytics rules in [`infra/sentinel/`](../infra/sentinel):

```sh
for f in infra/sentinel/*.json; do
  az deployment group create -g <sentinel-rg> -f "$f" -p workspace=<sentinel-workspace-name>
done
```

| Rule | Fires when |
|---|---|
| `approval-burst` | One approver approves more than 5 actions in 10 minutes |
| `policy-reject-protected` | A request is rejected for a protected user, device or indicator |
| `action-interrupted` | An action's outcome is unknown (check Defender) |
| `new-agent` | A new agent signs in for the first time |
| `broker-paused-or-principal-disabled` | Someone pauses the broker or disables a principal (informational) |
| `notify-failed` | Three or more notification failures in 15 minutes |
| `board-identity-misuse` | `blueboard-id-api` signs in from something other than the Function App (needs managed identity sign-in logs in the workspace) |

The rule templates are standard Sentinel scheduled-rule ARM templates. They haven't been imported into a live Sentinel workspace yet; tune the thresholds to your volumes.
