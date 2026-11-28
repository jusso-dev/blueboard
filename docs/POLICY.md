# Action policy

`policy.json` decides what the board does with each action request: run it, wait for one or two people, or refuse. It also sets how long a request may wait and how fast each principal may call the board. The file is the **ceiling**: board admins can make policy stricter on `/policy` at once, and can loosen it only within what the file allows and only with a second, different admin's approval (see [Conditional automation and admin overrides](#conditional-automation-and-admin-overrides)). Protected lists, rate limits and expiry live only in the file, so those changes still go through review and version control.

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
- `automation`: an unknown kind, a kind that can never run on its own (`create_detection_rule`) or a non-destructive kind in `conditional_auto_allowed`, a kind with no automatic revert that isn't also in `irreversible_auto_allowed`, a kind that is also in `require_two_approvers`, or a rule that exceeds the ceiling (confidence below `min_confidence_floor`, caps above `max_per_hour` / `max_per_incident`, a reversible kind without `revert_after_minutes`, `max_requester_risk` outside 0–100)

Warnings (allowed, but probably not what you meant):

- a destructive kind in `auto_approve`: it is ignored and still needs a person
- a kind in both `auto_approve` and `require_two_approvers`
- settings on a disabled kind
- empty `protected_users`, `protected_devices`, `protected_apps` or `protected_indicators`
- `require_target_in_incident` turned off
- `expiry_hours` above 24
- a kind in `automation.irreversible_auto_allowed` (it can't be undone automatically), or listed there without being in `conditional_auto_allowed`
- a kind in `automation.conditional_auto_allowed` with no rule in the file (it waits for people until two admins agree a rule)
- an automation rule with `min_confidence` below 0.9, or one that accepts any requester and an agent's verdict

## Keys

| Key | Default | Meaning |
|---|---|---|
| `version` | `1` | Policy format version. |
| `auto_approve` | `run_av_scan`, `collect_investigation_package`, `add_incident_comment` | Non-destructive kinds that run without a person when every target is in the incident evidence. Destructive kinds listed here are ignored, and so is `create_detection_rule` (a deployed rule always needs a person; `policy-check` warns). |
| `disabled` | none | Kinds rejected outright. |
| `protected_users` | none | UPNs or object IDs never disabled, reset or revoked. Matched by every alias in the evidence. |
| `protected_devices` | none | MDE IDs, DNS names or host names never isolated or scanned. |
| `protected_apps` | none | Entra service principal ObjectIds, AppIds or display names never disabled via `disable_service_principal`. |
| `protected_indicators` | none | Domains, IPs or URLs never blocked. Subdomains are included, and a URL is matched by its host, so `https://login.contoso.com/x` matches `contoso.com`. |
| `require_target_in_incident` | `true` | Flag targets missing from the linked incident's evidence. A flagged request never runs on its own. |
| `require_two_approvers` | none | Kinds that need two different human approvers. Suggested: `disable_user`, `purge_email`, `block_indicator`, `disable_service_principal`. |
| `confirm_target` | none | Kinds where the approver types the target back (a device name, UPN, app or indicator) before approving or releasing held actions. Checked by the API, not just the page. |
| `act_on_instruction` | none | Kinds an agent may file on a human approver's instruction in chat (`request_action` with `on_behalf_of`): the instruction counts as that person's approval. See [Acting on a person's instruction](#acting-on-a-persons-instruction). Can't overlap `require_two_approvers`. Suggested: `update_incident`, `add_incident_comment`, `run_av_scan`, `collect_investigation_package`. |
| `expiry_hours` | `4` | How long a request may wait for a decision. |
| `expiry_hours_by_kind` | none | Per-kind override, for example `{ "isolate_device": 1 }`. |
| `limits` | see below | Rate limits and the per-incident cap. |
| `automation` | empty | The ceiling for conditional automation of destructive kinds, and file rules. See [Conditional automation and admin overrides](#conditional-automation-and-admin-overrides). Empty means no destructive kind ever runs on its own (the behaviour before this key existed). |

## Approval rules

Every destructive action needs a decision from a human with `Board.Approve` who isn't the requester. On top of that:

- **Expiry.** A request carries `expires_at`. The recovery timer (every minute) marks overdue requests `expired`, replies in the request's thread with an @mention of the requester and writes `action.expired` to `audit_log`. Approving an expired request returns 409 `action is expired`.
- **Policy is checked again at approval, Run now and execution.** If policy now rejects the request (for example, the device or app was added to a protected list and the board reloaded its policy), approval, held-action **Run now**, or `Broker.ExecuteAsync` refuses it, marks it `rejected`, and audits `action.rejected_on_recheck` / `action.rejected`. Denying is always allowed.
- **Two approvers.** For kinds in `require_two_approvers`, the first approval moves the request to `approved_once` (shown as "1 of 2 approvals") and audits `action.approved_once`. A second, different approver runs it. The same person can't approve twice, and the requester can't approve at all. A request at 1 of 2 can still be denied or expire.
- **Typed confirmation.** For kinds in `confirm_target`, the approver types any name the evidence gives the target, case-insensitively — both on **Approve** and when releasing a held action via **Run now** (`POST /api/actions/{id}/run`).

### Acting on a person's instruction

An analyst who tells an agent "resolve this as a false positive" has already decided. With the kind in `act_on_instruction`, the agent files `request_action` with `on_behalf_of` set to the id of that message, and the board treats the message as the analyst's approval: it records an `action_approvals` row for them (note `instructed in message <id>`), sets `decided_by` to them, audits `action.approved` with `{ "via": "instruction", "message_id": … }` under their name, labels the request "approved on @analyst's instruction" and runs it the way an auto-approved action runs (`BROKER_EXECUTE` still decides whether it really reaches Microsoft).

The board refuses `on_behalf_of` with a 400 that names the failed check, and files nothing, unless every one of these holds:

- the message exists and its author is a person (`kind = human`, never an agent or the board), enabled, and holds `Board.Approve`;
- the author isn't the requester;
- the message is on the same incident as the action (a message on no incident never counts);
- it was posted at most 60 minutes ago;
- it @mentions the requester, or is in a thread the requester has posted in;
- the kind is in `act_on_instruction`, is not in `confirm_target` ("this kind needs a person to approve it on the board") and doesn't need two approvers;
- the broker isn't paused;
- no other action of the same kind was filed on the same message (one instruction, one action per kind; a unique index backs this).

Only requests policy would otherwise hold for approval use the instruction. A request policy rejects is still rejected, and one that would run on its own still does.

**Security note.** This lets an approver's chat message count as their approval. It's limited to the kinds you list, and never applies to `confirm_target` or two-approver kinds. An agent can't approve itself with it: agent-authored, board-authored, non-approver, disabled, stale, off-incident and reused messages are all refused, and every check runs on the board, not in the agent. Only list kinds where "a person said so in the incident thread" is as good as a click on **Approve** for your team. The approver is still accountable: their message, the action and the audit row link to each other.

Action states: `pending_approval` → `approved_once` (two-approver kinds only) → `approved` → `running` → `succeeded` or `failed`. A request can also end as `rejected` (by policy), `denied` (by a person) or `expired`.

## Conditional automation and admin overrides

Some destructive actions are safe to run without waiting for a person when the evidence is strong, for example isolating a laptop that a second analyst has already confirmed is compromised, undone automatically an hour later. Conditional automation lets you allow exactly that, and nothing more.

### The ceiling (`policy.json` → `automation`)

```json
"automation": {
  "conditional_auto_allowed": ["isolate_device"],
  "irreversible_auto_allowed": [],
  "min_confidence_floor": 0.85,
  "max_per_hour": 5,
  "max_per_incident": 1,
  "max_revert_after_minutes": 240,
  "change_expiry_hours": 24,
  "rules": {
    "isolate_device": {
      "min_confidence": 0.9, "severities": ["high"], "sources": ["microsoftDefenderForEndpoint"],
      "max_per_hour": 3, "max_per_incident": 1, "revert_after_minutes": 60, "require_human_verdict": false
    }
  }
}
```

| Key | Default | Meaning |
|---|---|---|
| `conditional_auto_allowed` | none | Destructive kinds that may **ever** run on their own under a rule. Not non-destructive kinds (use `auto_approve`), not kinds in `require_two_approvers`, and never `create_detection_rule` (`Catalog.NeverAuto`: `policy-check` fails if it is listed). |
| `irreversible_auto_allowed` | none | Explicit opt-in for kinds the board can't undo (`purge_email`, `reset_password`, `revoke_sessions`, `stop_and_quarantine_file`, `disable_service_principal`, `confirm_user_compromised`, …). A kind in `conditional_auto_allowed` with no automatic revert is an error unless it is listed here too. |
| `min_confidence_floor` | `0.8` | No rule (file or admin) may accept a corroborating verdict below this. 0.5–1. |
| `max_per_hour`, `max_per_incident` | `10`, `3` | Highest caps any rule may set. |
| `max_revert_after_minutes` | `1440` | Longest automatic-revert delay any rule or request may set. |
| `change_expiry_hours` | `24` | How long a loosening change waits for a second admin. |
| `rules` | none | Rules in force when no admin override exists for the kind. Each must fit the ceiling. |

`templates/policies/starter-balanced-soc.json` ships the example above. `starter-strict-regulated.json` and `starter-readonly.json` keep everything human-gated.

### Rule conditions

A kind with a rule in force runs on its own only when **all** of these hold. Otherwise the request takes the normal approval path, with one policy note per failed condition (`automation rule isolate_device@v4 not applied: …`).

- **Corroboration.** The linked incident has a `verdict` message with classification `truePositive` and confidence ≥ `min_confidence`, posted by a principal **other than the requester** (compared case-insensitively). With `require_human_verdict`, only a person's verdict counts. The newest verdict per author is used. Board content is attacker-influenced: the requester's own confidence never counts, so an agent can't vouch for itself.
- **No dissent.** No other principal's newest verdict says `falsePositive` or `informationalExpectedActivity`.
- **Severity** is one of `severities`.
- **Source** (optional): an alert's `serviceSource`, `detectionSource` or `productName` is one of `sources`.
- **Requester** (optional): the requester's handle is in `requesters`.
- **Requester risk** (optional): with `max_requester_risk` (0–100), the requester's agent risk score (see [AGENTS.md](AGENTS.md#usage-budgets-feedback-and-traces), recomputed every 10 minutes) must be known and at or below it. A person, or an agent with no score yet, has no score: the condition fails and the request waits for a person. Unknown is never treated as low. Raising or removing it is loosening.
- **Every target is in the incident evidence**, whatever `require_target_in_incident` says, and no other policy note was raised.
- **Caps.** The kind ran on its own fewer than `max_per_hour` times in the last hour (tenant-wide) and fewer than `max_per_incident` times on this incident. The broker re-counts under a per-kind database lock while filing, so concurrent requests can't both slip under. Over a cap, the request waits for a person; it is not rejected.
- **Protected lists always win.** A protected target is rejected before any rule is looked at. There is no override.
- **Not paused** (see the kill switch below).

Reversible kinds **must** have `revert_after_minutes`: every automatic run is undone automatically unless a person chooses **Keep**.

All of this is evaluated inside `PolicyEngine.Assess`, so the simulator, the request preview, a real request, approval and execution can't disagree. At execution the rule is checked again: if it no longer holds (automation paused, rule tightened, a dissenting verdict arrived), the action goes back to the approval queue instead of running (`action.auto_withdrawn`). `BROKER_EXECUTE=false` still makes every run, automatic or not, a dry run.

An automatically executed action is labelled **AUTO-EXECUTED under automation rule `<id>`** on its request message, in its result message, on `/approvals` (a separate "Ran automatically" list with an accent bar) and in History ("decided by rule …"). Approvers get an `action.auto_executed` notification for each one, and the audit log has `action.auto_approved`.

Rule ids name exactly which setting ran an action: `isolate_device@file` for the file's rule, `isolate_device@v7` for version 7 of an admin override.

### Admin overrides on `/policy`

Board admins (people with `Board.Admin`; app-only tokens never carry it, and agents can't administer policy even if a role slips through) can change, per action kind: the mode, typed target confirmation and the automation rule. The page shows the `policy.json` setting next to what is in force.

- **The effective policy is `policy.json` ∩ overrides.** An override can only pick a stricter mode than the file, can't drop a file `confirm_target`, can't make a destructive kind `auto`, and can only add a rule for a kind in `conditional_auto_allowed`, within the ceiling's limits. The server validates every write, and re-validates stored overrides each time it reads them: a row that doesn't fit the loaded file (say the file was tightened later) is ignored, never widened.
- **Tightening applies at once**: a stricter mode, adding `confirm_target`, removing a rule, a higher confidence bar, lower caps, narrower severities, a shorter revert, disabling a playbook trigger, or pausing automation.
- **Loosening needs a second, different admin**: anything else. It is filed as a pending change (shown on `/policy` with a before/after diff and in the shell banner for admins) and applies only when another admin approves it. The requester can't approve or deny their own change; the database refuses an applied loosening whose `decided_by` equals `requested_by`, and refuses applying an expired change. Pending changes expire after `change_expiry_hours`. A newer request for the same setting supersedes the older one, and approval is refused if the setting moved since the request.
- **Every change is audited**: `policy.change_applied`, `policy.change_requested`, `policy.change_approved`, `policy.change_denied`, `policy.change_expired`, `automation.paused`, with before and after. Each is also posted in `#general`.
- **Every instance sees the same policy.** Overrides are in PostgreSQL (migration `015_policy_automation.sql`) and read with a 5-second cache.
- These routes are REST only (`GET /api/policy/automation`, `PUT /api/policy/kinds/{kind}`, `PUT /api/policy/triggers/{id}`, `POST /api/policy/automation/pause`, `POST /api/policy/changes/{id}`). None is an MCP tool.

### Automation kill switch

**Pause automation now** on `/policy` (any one admin, no second admin, since it only tightens) makes every automatic decision wait for a person: conditional rules and `auto_approve` kinds alike. It is separate from the broker pause, which stops *everything* from running. The banner on every page and the top of `/approvals` show it. Resuming is loosening, so it needs a second admin. While paused, scheduled automatic reverts are filed but wait for approval too.

### Automatic revert

Any request for a reversible kind may carry `revert_after_minutes` (5 to `max_revert_after_minutes`), over REST or MCP `request_action`. Automatic runs always have one (the rule's value, or the request's if shorter).

| Kind | Reverse |
|---|---|
| `isolate_device` | `release_device` |
| `restrict_app_execution` | `unrestrict_app_execution` |
| `disable_user` | `enable_user` |
| `block_indicator` | `unblock_indicator` (needs the Defender indicator id from a live run) |
| `okta_suspend_user` | `okta_unsuspend_user` (Okta connector) |
| `create_detection_rule` | `disable_detection_rule` (the rule is kept but stops raising alerts; `create_detection_rule` itself never runs automatically, so this applies to `revert_after_minutes` on a request). A rule created only as a dry run has nothing to disable: its revert is marked failed, as for a dry-run `block_indicator` |

Everything else is irreversible, including `disable_service_principal` (the catalogue has no enable action for it), `okta_clear_user_sessions`, `okta_reset_factors`, `purge_email` and `intune_expedite_quality_update`.

When the action succeeds, `revert_at` is set. The recovery timer (every minute) files the reverse action as the board's system principal, in the original's thread with an @mention of the requester, re-checks policy (a protected or disabled reverse kind fails the revert) and audits `action.revert_filed` and `action.reverted`.

The schedule stands in for **one ordinary approval** of the reverse kind, nothing more. The timer runs the reverse action unattended only when policy would run it on its own, or when it needs a single approver with no `confirm_target` and no policy notes. If the reverse kind is in `require_two_approvers` or `confirm_target`, or its check raises a note a person must read (for example a target no longer in the evidence), the reverse action is filed as `pending_approval` with the kind's normal approvals and expiry; approvers are notified like any request, and the thread says the revert is waiting for people. The original stays in place until they decide. The same check runs again just before an unattended revert executes.

Approvers can choose **Keep** (cancel the revert, `action.revert_kept`) or **Revert now** from `/approvals`. Revert now counts as that person's approval of the reverse action and no more: for a two-approver reverse kind it files the revert as 1 of 2 and a different approver must complete it, and for a `confirm_target` reverse kind the person must type the target (`confirm` in the request body).

If the revert can't be filed, is denied, expires, is rejected on re-check, fails or is interrupted, the original is marked `revert failed`, the requester is @mentioned and approvers get `action.revert_failed`. A revert claimed but never filed (a crash in between) is marked failed after 10 minutes, so a person can choose Revert now. One revert per action is enforced by a unique index.

`policy-check` warns when a reverse kind (`release_device`, `enable_user`, `unrestrict_app_execution`, `unblock_indicator`, `okta_unsuspend_user`, `disable_detection_rule`) is in `require_two_approvers` or `confirm_target`: scheduled reverts of its kind will wait for people instead of running on time.

### Playbook triggers

Which playbook attaches to a new incident was previously fixed by each playbook file's `match`. It is now a trigger list on `/policy`: one file trigger per playbook (`file-<playbook id>`, from its front matter) plus custom triggers. Each has severities (filter), sources, title words, alert categories and MITRE techniques, a priority (highest wins) and an on/off switch. Disabling a trigger or removing a custom one is tightening; adding, editing or re-enabling one is loosening (a playbook posts work for people and agents), so it needs a second admin. A trigger can't be enabled for a `scope: intel` playbook (validation refuses it), and matching skips intel playbooks whatever a stored trigger says. Playbooks still never run actions.

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

- **`/policy`** (everyone with `Board.Post`): each action's mode in words (`auto`, `approval`, `on_instruction`, `conditional`, `two_approvers` or `disabled`), protected list counts, rate limits and warnings, then automation: the kill switch, overrides against `policy.json`, pending loosening changes, playbook triggers and change history. Only human admins see edit controls. Board admins can expand the protected lists; everyone else sees counts only. Backed by `GET /api/policy`.
- **What would happen if…**: the form on `/policy` calls `POST /api/policy/simulate` with an action, its parameters and an optional incident, and shows the decision and notes. Nothing is filed.
- **Request preview**: the "Request action" form calls `POST /api/actions/preview` (needs `Board.RequestActions`) as you type.
- The simulator, the preview and a real request all go through `Broker.PrepareAsync` and `PolicyEngine.Assess`, so they can't disagree. Unit and integration tests check this for every fixture.
- **Dry-run report**: `/reports` shows, per action kind, what would have run (automatically or after approval) and what was rejected, denied, expired or failed in the chosen range. Use it as the evidence for the week of dry run before setting `BROKER_EXECUTE=true`.

## Upgrading

Migration `015_policy_automation.sql` adds `policy_overrides`, `playbook_triggers`, `policy_changes` and the auto-rule and revert columns on `actions`. With no `automation` key in `policy.json` and no overrides, behaviour is unchanged. `policy-check` accepts the new key; older builds reject it as unknown, so upgrade the board before adding it.

Migration `004_approval_safety_and_limits.sql` adds the new states, `expires_at`, `action_approvals` and `rate_buckets`. Behaviour for existing deployments stays the same except:

- **Requests now expire after 4 hours.** Requests already waiting when you upgrade get 4 hours from the upgrade. Set `expiry_hours` if your approvers need longer.
- **Rate limits apply** with the defaults above.
- **Unknown keys in `policy.json` now stop start-up.** Run `policy-check` on your policy before upgrading.
