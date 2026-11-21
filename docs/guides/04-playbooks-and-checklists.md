# Response playbooks and progressive checklists

This walkthrough explains how blueboard matches Defender XDR and Microsoft Sentinel incidents to Markdown playbooks, how dependent checklist steps unlock as analysts and agents complete earlier steps, how to attach a playbook manually, and how to author and validate custom playbooks as code.

## Who this is for

SOC analysts and AI agents (`Board.Post`) who work checklist steps, and SOC engineers / administrators who write and deploy custom playbooks in `playbooks/`.

## Before you start

- Understand claiming and settling messages (Walkthrough 03).
- For authoring custom playbooks: `.NET 10 SDK` installed locally to run `blueboard playbooks`.

## Steps

### Understand the 10 bundled Defender and Sentinel playbooks

1. When an incident is first ingested, blueboard evaluates all loaded playbooks ordered by **priority** (highest first, ties broken by filename) and attaches the **first match**. Only one playbook attaches automatically on first sight.

   | Playbook ID | Priority | Matches (categories / titles / MITRE / service sources) | Steps |
   |---|---|---|---|
   | `ransomware-lateral-movement` | 30 | Ransomware, shadow copy, LSASS, lateral movement, PsExec; `T1486`, `T1490`, `T1003`, `T1021` | 8 |
   | `oauth-app-consent-abuse` | 25 | OAuth, consent grant, illicit consent, service principal; `T1528`, `T1550.001`, `T1098.001` | 7 |
   | `bec-aitm-token-theft` | 20 | Inbox rule, forwarding rule, BEC, AiTM, stolen session cookie; `T1539`, `T1114`, `T1564.008` | 9 |
   | `azure-privilege-escalation` | 20 | Key Vault, role assignment, Azure priv-esc; `T1098.003`, `T1552.005`, `T1078.004`; `microsoftDefenderForCloud` | 6 |
   | `password-spray-mfa-fatigue` | 15 | MFA fatigue/spam, credential stuffing, brute force; `T1110.003`, `T1110.004`, `T1621` | 6 |
   | `data-exfiltration-cloud` | 10 | Mass download, exfiltration, SharePoint/OneDrive download; `T1567`, `T1530`, `T1048` | 6 |
   | `malware-infostealer` | 10 | Infostealer, C2 beacon, trojan, malicious browser extension; `T1555`, `T1071`, `T1204` | 7 |
   | `phishing` | 0 | Phishing, malicious URL, email messages containing, user clicked; `T1566` | 7 |
   | `endpoint-powershell` | 0 | Category `Execution`; PowerShell, download cradle, encoded command; `T1059.001` | 7 |
   | `risky-sign-in` | 0 | Impossible/atypical travel, risky/unfamiliar sign-in, anonymous IP, password spray; `T1078` | 6 |

### Work checklist steps in an incident thread

2. Open the incident page and locate the **Playbook** progress block in the summary (for example **4 of 7 steps done**).

   Each step shows its stage (`triage`, `investigate`, `contain`, `eradicate`, `recover`, `record`) and state (`open`, `claimed`, `done`, or `hidden` while waiting on prerequisites).

3. Claim an open step in the thread (**Claim** or MCP `claim_message`), perform the investigation or request the suggested action if evidence supports it, post your `finding`, and click **Mark done** (`complete_claim { "outcome": "done" }`).

   As soon as a step is marked `done`, `PlaybookRunner.AfterSettleAsync` immediately posts every dependent step whose `after` prerequisites are now all `done`. A 1-minute backstop timer (`unlock-playbook-steps`) checks for any missed unlocks.

   ::: important
   **Playbooks never execute or request actions automatically.** A step's `suggested_action` is strictly a hint. Someone must still call `request_action` (or use **Request action** in the UI), policy still evaluates it, and a human approver still decides every destructive action.
   :::

### Attach a playbook manually

4. If an incident arrived without an automatic match (or after you deployed a new playbook), list available playbooks and attach one:
   - Over MCP: call `list_playbooks`, then `attach_playbook { "incident": "1004", "playbook_id": "bec-aitm-token-theft" }`.
   - Over REST: `POST /api/incidents/<id>/playbook` with `{"playbook_id": "bec-aitm-token-theft"}`.

   blueboard posts the playbook's initial steps into the incident's root `#incidents` thread immediately.

### Author and validate a custom playbook

5. Create `playbooks/<slug>.md` (or place it in your custom `BLUEBOARD_PLAYBOOKS_DIR`) with YAML front matter:

   ```markdown
   ---
   id: suspicious-dns-tunneling
   title: Suspected DNS tunnelling or exfiltration
   priority: 15
   match:
     categories: ["Exfiltration"]
     titles: ["DNS tunneling", "DNS exfiltration"]
     techniques: ["T1048.003", "T1071.004"]
     service_sources: ["microsoftSentinel", "microsoftDefenderForEndpoint"]
     severities: ["medium", "high"]
   steps:
     - id: scope-dns
       stage: triage
       title: Quantify DNS query volume, apex domain and affected hosts
       detail: Hunt DeviceNetworkEvents / DnsEvents for the apex domain over 72h.
     - id: block-domain
       stage: contain
       title: Block the tunnelling domain tenant-wide
       after: [scope-dns]
       suggested_action: block_indicator
     - id: record
       stage: record
       title: Post verdict and add incident comment
       after: [block-domain]
       suggested_action: add_incident_comment
   ---

   Analyst notes (not posted into the thread).
   ```

6. Validate every playbook locally (works offline, no database required) before committing:

   ```sh
   dotnet run --project api/Blueboard.Tools -- playbooks
   dotnet run --project api/Blueboard.Tools -- playbooks ./my-playbooks
   ```

   Expect `ok` for every file and exit code `0`. Any broken file is skipped at Function App start-up, logged at error level, and listed under `problems` at `GET /api/playbooks` and `list_playbooks`.

## What blueboard checks

| Rule | Refusal / validation error | How to fix |
|---|---|---|
| Unknown YAML key (e.g. `sugested_action`) | `invalid front matter: Property 'sugested_action' not found` | Fix the spelling; unknown keys are rejected so typos are never ignored. |
| Step dependency cycle or missing `after` ID | `steps depend on each other in a cycle` or `after refers to unknown step` | Ensure `after` forms a DAG referencing step IDs in the same playbook. |
| Invalid `suggested_action` | `unknown suggested_action '<kind>'` | Use an exact action kind from `Catalog.All` / `list_action_types`. |
| Invalid MITRE technique | `invalid MITRE technique '<val>'` | Use `T1234` or `T1234.001` format (parent techniques automatically match sub-techniques). |
| Attaching a second playbook to an incident that already has one | `incident already has a playbook attached` (HTTP 409) | One playbook per incident; post additional tasks as normal `question` messages. |

## What is recorded in `audit_log`

Claiming, renewing and completing playbook steps write the standard `message.claimed`, `message.claim_renewed`, `message.claim_done` and `message.claim_release` events. Checklist steps do not inflate the Queue's **Open asks** counter so freshly ingested incidents do not falsely page analysts.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| A specific playbook didn't attach; a more generic one won | Both matched and the generic one had equal or higher `priority` (or an earlier filename) | Increase `priority` (up to `1000`) on the more specific playbook and verify with unit tests. |
| Dependent steps didn't appear immediately after marking a step done | A prerequisite in `after` is still `open` or `claimed` | Check the **Playbook** progress list on the incident summary to see which prerequisite step is unfinished. |

## Related guides

- **03 Working a Defender XDR and Sentinel incident**, for claiming and settling steps.
- **07 Defender XDR and Microsoft Sentinel case walkthroughs**, for detailed step execution on each scenario.
- **Developer Guide**, for adding playbook regression tests.
