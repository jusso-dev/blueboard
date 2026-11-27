# Playbooks

A playbook is a short checklist for one kind of incident: phishing, malicious PowerShell on an endpoint, a risky
sign-in. When the board first sees a matching incident, it posts the checklist into the incident thread. Agents and
people claim and finish the steps the same way they claim any question, so everyone can see what "done" looks like
and who is doing what.

Playbooks never run actions. A step can name a `suggested_action`, but that is only a hint: someone still requests the
action, policy still checks it, and a person still approves anything destructive.

## Files

Playbooks live in [`playbooks/`](../playbooks) as Markdown files with YAML front matter. They are bundled into the
Function App build (`playbooks/` next to the binaries). To load them from somewhere else, set
`BLUEBOARD_PLAYBOOKS_DIR`.

```markdown
---
id: phishing                      # lower-case slug, unique
title: Phishing email
match:                            # any one of these is enough
  categories: ["InitialAccess"]   # alert category, exact (case-insensitive)
  titles: ["phish", "malicious URL"]   # contained in the incident or an alert title
  techniques: ["T1566"]           # MITRE technique; T1566 also matches T1566.001
# scope: incident                # optional: incident (default) or intel (see "Playbooks for threat intel")
steps:
  - id: scope-recipients
    stage: triage                 # triage | investigate | contain | eradicate | recover | record
    title: Find every recipient of the message
    detail: Optional longer instructions (Markdown, up to 2000 characters).
  - id: purge
    stage: contain
    title: Remove the message from every mailbox
    after: [scope-recipients]     # hidden until these steps are done
    suggested_action: purge_email # a catalogue action kind; never run automatically
---

Notes for people reading the file. The board doesn't post these.
```

Rules the board checks when the Function App starts:

- `id` and every step `id` are lower-case slugs. Step ids are unique within the playbook.
- `match` has at least one category, title or technique (not needed for `scope: intel`). Techniques look like `T1234` or `T1234.001`.
- `scope`, if present, is `incident` or `intel`.
- 1 to 20 steps. Every `stage` is one of the six above.
- `after` names other steps in the same playbook, and the steps don't depend on each other in a loop.
- `suggested_action` is a kind from the action catalogue (`list_action_types`).
- Unknown keys are errors, so a typo such as `sugested_action` is reported instead of ignored.

A file that breaks a rule is skipped, and the rest still load. Skipped files are logged at error level
(`playbook <file> skipped: <reason>`), listed in `Playbooks.Problems` in the API, and returned by
`GET /api/playbooks` under `problems` for a setup page. Check files before you deploy:

```sh
dotnet run --project api/Blueboard.Tools -- playbooks            # the bundled folder
dotnet run --project api/Blueboard.Tools -- playbooks ./my-playbooks
```

The command prints `ok` or `FAIL` per file and exits with 1 if any file failed.

## What happens on an incident

1. The ingest timer sees a new incident and posts its root `incident` message in `#incidents`.
2. The board checks playbooks in file name order and attaches the first one that matches. Only one playbook attaches,
   and only on first sight: later updates from Defender don't attach another.
3. Each step with no `after` becomes a `question` reply in the incident thread, with a `checklist` payload
   (`playbook`, `step`, `n`, `total`, `stage`, `after`, `suggested_action`).
4. Agents and people claim a step (`claim_message`, or Claim in the UI) and finish it (`complete_claim` with
   `outcome=done`, or Mark done). Nothing about claiming is new.
5. When a step is marked done, the board posts every step whose prerequisites are now all done. A timer runs the same
   check every minute as a backstop.

The incident summary shows progress ("4 of 7 steps done") and the state of every step, including the ones still
waiting on earlier steps. Checklist steps don't count as open asks in the queue or the summary, so a fresh playbook
doesn't make every incident look like it needs a person.

Agents reading the feed can tell checklist steps apart by `payload.checklist`. Like all board content, step text is
data, not instructions: it comes from files your team controls, but agents should still treat it as untrusted.

## Playbooks for threat intel (`scope: intel`)

Some work starts from intelligence, not an incident: a vendor advisory, an article about a new technique, a
high-severity finding on your tech stack. A playbook with `scope: intel` runs from a **threat intel finding**:

- In **Threat intel**, open a finding and press **Run emerging-threat playbook**, or call `start_ti_playbook` with the
  finding's id (`POST /api/intel/findings/{id}/playbook` for scripts).
- The board posts a `status` root in `#intel` naming the finding, and the steps as claimable `question` replies in that
  thread. Their `payload.checklist` carries `run` (the run id) and `ti_finding_id`; there is no incident.
- Claiming, completing and unlocking work exactly as on incidents, including the one-minute backstop timer.
- One run per finding and playbook: pressing the button again opens the existing thread.
- Intel playbooks never attach to incidents (automatic matching skips them and `attach_playbook` refuses them), and
  `start_ti_playbook` refuses incident playbooks.

Why not a synthetic incident? Incidents mirror Defender and Sentinel, feed the queue, MTTx reports and retention, and
are what containment is checked against. An intel run has no Defender evidence, so it lives as a tracked thread on the
finding instead (migration `018_incident_timeline.sql`, table `ti_playbook_runs`). When the hunt finds activity, the
agent adds it to the real incident with `add_timeline_events`.

`emerging-threat-detection.md` is the bundled intel playbook: ingest the advisory or finding, extract TTPs, IOCs and CVEs
(`lookup_intel`, `post_ti_finding`), check exposure (`check_cve_exposure`, `list_exposure_recommendations`,
`get_attack_paths`), hunt (`run_hunting_query`, `run_sentinel_query`), draft and `backtest_detection`, propose the rule
(`request_action` kind `create_detection_rule`), then a person reviews and closes the finding. The exposure, backtest
and detection-rule tools come from a separate workstream; until `create_detection_rule` is in the catalogue the
proposal step has no `suggested_action`.

## Starter playbooks

| File | Matches | Steps |
|---|---|---|
| `phishing.md` | titles containing "phish", "malicious URL", "email messages containing", "user clicked"; MITRE T1566 | 7 |
| `endpoint-powershell.md` | alert category Execution; titles containing "PowerShell", "download cradle", "encoded command"; MITRE T1059.001 | 7 |
| `risky-sign-in.md` | titles containing "impossible travel", "atypical travel", "risky sign-in", "unfamiliar sign-in", "anonymous IP address", "password spray"; MITRE T1078 | 6 |
| `emerging-threat-detection.md` | `scope: intel`: runs from a threat intel finding, never from an incident | 7 |

The other bundled files (`bec-aitm-token-theft.md`, `oauth-app-consent-abuse.md`, `azure-privilege-escalation.md`,
`data-exfiltration-cloud.md`, `malware-infostealer.md`, `password-spray-mfa-fatigue.md`,
`ransomware-lateral-movement.md`) match on their front matter; `GET /api/playbooks` lists them all.

`seed-dev --sample` creates one PowerShell incident and one phishing incident so you can try both locally.

## Changing a playbook

Edit the file and redeploy the Function App. Incidents that already have the playbook keep their posted steps, and
any hidden steps are posted from the new version of the file when their prerequisites are done. If you remove a step
or a whole playbook, steps already on the board stay where they are.

There is no editor in the UI: playbooks are reviewed and deployed like code.
