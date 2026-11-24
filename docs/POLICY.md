# Action policy

`policy.json` decides what the board does with each action request: run it, wait for one or two people, or refuse. It also sets how long a request may wait and how fast each principal may call the board. The file is the only place policy lives. Nothing in the UI edits it, so every change goes through review and version control.

- In Azure the file is passed to Bicep as a secure parameter (stored in Key Vault in the `production` profile), injected as `BLUEBOARD_POLICY_JSON`, and parsed directly in memory at start-up with zero temporary files written to disk.
- Locally, `BLUEBOARD_POLICY_FILE` points at it. With no file configured the board uses the built-in defaults below.
- A configured file that is missing or invalid stops the Function App at start-up with the reason in the log. It does not fall back to defaults.

## Check a policy before you deploy

```sh
dotnet run --project api/Blueboard.Tools -- policy-check policy.json
```

It prints one row per action (target type, mode, whether the approver must type the target, expiry), the protected list counts, the rate limits and any warnings. It exits with 1 on an error, so CI and `infra/deploy.sh` both run it. CI checks `policy.example.json` on every push.

Errors (the board won't start):

- an unknown key, for example `auto_aprove` (`unknown key auto_aprove`)
- an unknown action kind in any list
- `version` other than `1`
- expiry hours outside 0–720, or a rate limit outside its range

Warnings (allowed, but probably not what you meant):

- a destructive kind in `auto_approve`: it is ignored and still needs a person
- a kind in both `auto_approve` and `require_two_approvers`
- settings on a disabled kind
- empty `protected_users`, `protected_devices`, `protected_apps` or `protected_indicators`
- `require_target_in_incident` turned off
- `expiry_hours` above 24

## Keys

| Key | Default | Meaning |
|---|---|---|
| `version` | `1` | Policy format version. |
| `auto_approve` | `run_av_scan`, `collect_investigation_package`, `add_incident_comment` | Non-destructive kinds that run without a person when every target is in the incident evidence. Destructive kinds listed here are ignored. |
| `disabled` | none | Kinds rejected outright. |
| `protected_users` | none | UPNs or object IDs never disabled, reset or revoked. Matched by every alias in the evidence. |
| `protected_devices` | none | MDE IDs, DNS names or host names never isolated or scanned. |
| `protected_apps` | none | Entra service principal ObjectIds, AppIds or display names never disabled via `disable_service_principal`. |
| `protected_indicators` | none | Domains, IPs or URLs never blocked. Subdomains are included, and a URL is matched by its host, so `https://login.contoso.com/x` matches `contoso.com`. |
| `require_target_in_incident` | `true` | Flag targets missing from the linked incident's evidence. A flagged request never runs on its own. |
| `require_two_approvers` | none | Kinds that need two different human approvers. Suggested: `disable_user`, `purge_email`, `block_indicator`, `disable_service_principal`. |
| `confirm_target` | none | Kinds where the approver types the target back (a device name, UPN, app or indicator) before approving or releasing held actions. Checked by the API, not just the page. |
| `expiry_hours` | `4` | How long a request may wait for a decision. |
| `expiry_hours_by_kind` | none | Per-kind override, for example `{ "isolate_device": 1 }`. |
| `limits` | see below | Rate limits and the per-incident cap. |

## Approval rules

Every destructive action needs a decision from a human with `Board.Approve` who isn't the requester. On top of that:

- **Expiry.** A request carries `expires_at`. The recovery timer (every minute) marks overdue requests `expired`, replies in the request's thread with an @mention of the requester and writes `action.expired` to `audit_log`. Approving an expired request returns 409 `action is expired`.
- **Policy is checked again at approval, Run now and execution.** If policy now rejects the request (for example, the device or app was added to a protected list and the board reloaded its policy), approval, held-action **Run now**, or `Broker.ExecuteAsync` refuses it, marks it `rejected`, and audits `action.rejected_on_recheck` / `action.rejected`. Denying is always allowed.
- **Two approvers.** For kinds in `require_two_approvers`, the first approval moves the request to `approved_once` (shown as "1 of 2 approvals") and audits `action.approved_once`. A second, different approver runs it. The same person can't approve twice, and the requester can't approve at all. A request at 1 of 2 can still be denied or expire.
- **Typed confirmation.** For kinds in `confirm_target`, the approver types any name the evidence gives the target, case-insensitively — both on **Approve** and when releasing a held action via **Run now** (`POST /api/actions/{id}/run`).

Action states: `pending_approval` → `approved_once` (two-approver kinds only) → `approved` → `running` → `succeeded` or `failed`. A request can also end as `rejected` (by policy), `denied` (by a person) or `expired`.

## Rate limits

Each principal has a token bucket per kind of call, stored in PostgreSQL so every Function App instance shares it. A bucket holds up to `capacity` calls and refills evenly over `per_seconds`.

| Bucket | Covers | Agents | People |
|---|---|---|---|
| `post` | posting messages and scheduling follow-ups (`schedule_followup`) | 60 per minute | 120 per minute |
| `hunt` | `run_hunting_query` and `run_sentinel_query` | 10 per minute | 30 per minute |
| `lookup` | `lookup_entity` and `lookup_purview_context` | 30 per minute | 120 per minute |
| `action_request` | requesting actions | 5 per 10 minutes | 30 per 10 minutes |
| `claim` | claiming messages and webhook `subscribe` calls | 60 per minute | 120 per minute |

`limits.pending_actions_per_incident` (default 10) caps how many actions can wait for approval on one incident at a time.

When a limit is hit:

- REST returns `429` with a `Retry-After` header and `rate limited: <bucket>, retry in Ns`.
- MCP tools return `error: rate limited: <tool>, retry in Ns`, and nothing reaches Microsoft Graph.
- `audit_log` gets a `limit.hit` row with the principal and bucket, at most once a minute per bucket.
- The board's own system principal is never limited.

Override any bucket per principal kind; unset buckets keep their defaults:

```json
"limits": {
  "pending_actions_per_incident": 10,
  "agent": { "hunt": { "capacity": 5, "per_seconds": 60 } },
  "human": {}
}
```

Front Door or WAF rate limits are still worth adding in production. These limits stay in the app so they hold per principal, not per IP.

## Seeing and testing policy on the board

- **`/policy`** (everyone with `Board.Post`): each action's mode in words, protected list counts, rate limits and warnings. Board admins can expand the protected lists; everyone else sees counts only. Backed by `GET /api/policy`.
- **What would happen if…**: the form on `/policy` calls `POST /api/policy/simulate` with an action, its parameters and an optional incident, and shows the decision and notes. Nothing is filed.
- **Request preview**: the "Request action" form calls `POST /api/actions/preview` (needs `Board.RequestActions`) as you type.
- The simulator, the preview and a real request all go through `Broker.PrepareAsync` and `PolicyEngine.Assess`, so they can't disagree. Unit and integration tests check this for every fixture.
- **Dry-run report**: `/reports` shows, per action kind, what would have run (automatically or after approval) and what was rejected, denied, expired or failed in the chosen range. Use it as the evidence for the week of dry run before setting `BROKER_EXECUTE=true`.

## Upgrading

Migration `004_approval_safety_and_limits.sql` adds the new states, `expires_at`, `action_approvals` and `rate_buckets`. Behaviour for existing deployments stays the same except:

- **Requests now expire after 4 hours.** Requests already waiting when you upgrade get 4 hours from the upgrade. Set `expiry_hours` if your approvers need longer.
- **Rate limits apply** with the defaults above.
- **Unknown keys in `policy.json` now stop start-up.** Run `policy-check` on your policy before upgrading.
