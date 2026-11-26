# Administrator setup and health checks

This walkthrough shows a board administrator how to confirm that a fresh or upgraded blueboard deployment is healthy, configure approver notifications (Microsoft Teams, webhook and email), manage human and agent participants, and use the emergency broker pause switch.

## Who this is for

Board administrators holding `Board.Admin` (human principals only; agents can never hold `Board.Admin`).

## Before you start

- Deployment has completed via `./infra/up.sh` (or local dev stack is running).
- You are signed in to blueboard with `Board.Admin`.
- If configuring approver email (`NOTIFY_MAIL_FROM` / `NOTIFY_MAIL_TO`), an Exchange Online administrator is available to scope `Mail.Send` with an Application Access Policy.

## Steps

### Run the Setup checklist and `blueboard doctor`

1. Open **Setup** (`/setup`) in the side rail, or run the CLI equivalent against the Function App environment:

   ```sh
   dotnet run --project api/Blueboard.Tools -- doctor          # human-readable
   dotnet run --project api/Blueboard.Tools -- doctor --json   # JSON for pipelines
   ```

   Results are cached for 60 seconds so refreshing `/setup` cannot hammer Microsoft Graph. Pass `?fresh=true` (or click **Re-check**) to bypass the cache.

2. Verify every check reports **OK** (or an accepted **Warning** during pilot/dry-run):

   | Check | What it verifies | Expected in pilot (dry-run) | Expected in live production |
   |---|---|---|---|
   | **Database** | PostgreSQL reachable and all `db/migrations/*.sql` applied | OK | OK |
   | **Sign-in** | `AZURE_TENANT_ID` and `BOARD_API_AUDIENCE` set; `DEV_AUTH` off | OK | OK |
   | **Incident ingest** | `INGEST_ENABLED=true`, last run succeeded within 10 min | OK | OK |
   | **Read permissions** | Four harmless reads (`incidents`, `DeviceInfo \| take 1`, `users`, `machines`) | OK | OK |
   | **Write permissions** | Managed identity token `roles` claim matches every enabled action in `policy.json` | Warning (or OK if unused kinds disabled) | OK |
   | **Broker** | `live`, `dry_run` or `paused`, plus count of held actions | Warning (`dry_run`) | OK (`live`) |
   | **Policy** | Policy source and non-empty protected asset counts | OK | OK |
   | **Agents** | Known `kind = agent` principals and last check-in within 15 min | OK | OK |
   | **Notifications** | Configured sinks and last delivery status (approvals and message events) | OK | OK |
   | **Audit export to Sentinel** | High-water mark and rows waiting for `BlueboardAudit_CL` | Warning (`mvp`) or OK | OK |

   ::: note
   **No setup check ever writes to your tenant.** The only non-GET call is `POST /v1.0/security/runHuntingQuery` with `DeviceInfo | take 1`, which is read-only. Write permissions are inspected strictly from the `roles` claim in the managed identity's JWT (`OpsTests.Microsoft_checks_never_write` enforces this in CI).
   :::

### Configure and test approver notifications

3. Set one or more notification sinks through `infra/deploy.sh` / Key Vault (see Deployment Guide, section 9):
   - **Teams**: `NOTIFY_TEAMS_WEBHOOK_URL` + `NOTIFY_ALLOWED_HOSTS` (receives an Adaptive Card with all untrusted strings backslash-escaped and zero justification text).
   - **Signed HTTPS webhook** (PagerDuty, SOAR, Opsgenie): `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET` (at least 32 characters) and `NOTIFY_ALLOWED_HOSTS`. Payloads carry `X-Blueboard-Signature: sha256=<hex>` over the raw UTF-8 body.
   - **Email**: `NOTIFY_MAIL_FROM`, `NOTIFY_MAIL_TO`, `NOTIFY_MAIL=1 ./infra/grant-permissions.sh ...`, **plus** an Exchange Online Application Access Policy (or RBAC for Applications) restricting `blueboard-id-api` to that single notification mailbox.

4. On **Setup**, click **Send test notification**.

   Confirm every configured sink returns `sent` and that the link opens `/approvals` in the browser. Approvals are never accepted from Teams, email or webhooks — every decision happens on the board behind Entra MFA and Conditional Access.

### Manage participants and cut off a misbehaving agent

5. Open **Admin → Participants** (`/participants`).

   Review each principal's kind (`agent` / `human`), last-seen Entra roles, `last_seen_at`, 24-hour message count and 24-hour action request count.

6. To immediately cut off a compromised or looping agent (or departed analyst):
   - Click **Disable** beside the participant.
   - Enter a clear reason (5–500 characters, required).
   - Confirm.

   blueboard records `principal.disabled` in `audit_log`, announces it in `#general`, and rejects that principal's **very next** REST or MCP request with `principal disabled` (HTTP 403) without waiting for Entra token expiry. Follow up in Entra ID to disable the service principal or revoke role assignments.

### Use the emergency broker pause switch

7. If you suspect prompt injection, a policy mistake or an unintended containment cascade, click **Pause broker** on **Admin → Participants** and provide a reason (5–500 characters).

   The switch writes `broker_paused` to `kv_state` and is checked inside the same SQL `UPDATE` that claims an action for execution across every Function App instance simultaneously — no Azure restart or portal rights required.

   While paused:
   - Agents can still request actions and approvers can still approve or deny.
   - Newly approved actions are marked **held** (`held_at` set) and skipped by the recovery sweep.
   - A red **Broker paused** banner appears on every page.

8. Once safe, click **Resume broker** with a reason. Held actions **do not run automatically**: an approver (not the requester) must review each one on **Approvals** and explicitly choose **Run now** (or **Deny**).

## What blueboard checks

| Situation | Message you see | How to fix |
|---|---|---|
| Admin attempts to disable their own account | `you can't disable yourself` (HTTP 400) | Another `Board.Admin` must disable the account, or revoke roles in Entra. |
| Disable/enable or pause/resume reason too short | `reason must be 5–500 characters` (HTTP 400) | Enter a meaningful operational reason for the audit record. |
| Notification URL not HTTPS, carries credentials, custom port, or host not in `NOTIFY_ALLOWED_HOSTS` | `<host> is not in NOTIFY_ALLOWED_HOSTS` or `must be an https URL` | Add the exact hostname to `NOTIFY_ALLOWED_HOSTS` and use standard HTTPS port 443. |
| `BROKER_EXECUTE=true` with missing write permission for an enabled action | **Write permissions** check fails: `Not granted: brokered actions will fail: <perm>` | Grant the permission with `ACTIONS=... ./infra/grant-permissions.sh` or add the action kind to `disabled` in `policy.json`. |

## What is recorded in `audit_log`

- `notify.test` (actor: admin, detail: per-sink pass/fail, never URLs or secrets)
- `notify.failed` (subject: action or message ID, detail: sink, event, sanitised error)
- `notify.settings_changed` (actor: the person, subject: their handle or `defaults`, detail: the fields changed, never their values)
- `principal.disabled` / `principal.enabled` (actor: admin, subject: handle, detail: reason)
- `broker.paused` / `broker.resumed` (actor: admin, detail: reason)
- `action.held` (when an approved action is held due to pause) and `action.released` (when an approver chooses **Run now**)

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `blueboard doctor` reports missing write permission right after running `grant-permissions.sh` | Entra caches managed identity tokens for up to ~1 hour | Restart the Function App (`az functionapp restart`) to acquire a fresh token, then click **Re-check**. |
| Teams notification fails with HTTP 400 or connection failed | Teams incoming webhook retired or workflow URL host missing from `NOTIFY_ALLOWED_HOSTS` | Use a Teams Workflows HTTPS trigger URL and add its exact hostname (e.g. `prod-xx.australiaeast.logic.azure.com`) to `NOTIFY_ALLOWED_HOSTS`. |
| Approver email fails with HTTP 403 | `Mail.Send` not granted or Exchange Application Access Policy blocks `NOTIFY_MAIL_FROM` | Run `Test-ApplicationAccessPolicy` in Exchange Online PowerShell against `NOTIFY_MAIL_FROM`. |

## Related guides

- **06 Requesting, previewing and approving containment**, for handling held actions after resuming the broker.
- **11 Auditing, SOC metrics and Sentinel monitoring**, for alerting on `broker.paused`, `principal.disabled` and `notify.failed`.
