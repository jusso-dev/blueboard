---
id: risky-sign-in
title: Risky or impossible-travel sign-in
match:
  titles: ["impossible travel", "atypical travel", "risky sign-in", "unfamiliar sign-in", "anonymous IP address", "password spray"]
  techniques: ["T1078"]
steps:
  - id: review-sign-ins
    stage: triage
    title: Review the user's recent sign-ins
    detail: Locations, IP addresses, devices, client apps and whether MFA was satisfied. Post the suspicious sign-ins as a finding.
  - id: confirm-with-user
    stage: investigate
    title: Confirm with the user or their manager
    detail: Ask whether they travelled, used a VPN or a new device. Post the answer.
  - id: check-persistence
    stage: investigate
    title: Check for mailbox rules, new MFA methods and app consents
    after: [review-sign-ins]
  - id: revoke
    stage: contain
    title: Revoke the user's sessions
    after: [review-sign-ins]
    suggested_action: revoke_sessions
  - id: reset
    stage: eradicate
    title: Force a password reset
    after: [revoke]
    suggested_action: reset_password
  - id: record
    stage: record
    title: Post a verdict and note the outcome on the Defender incident
    after: [reset, check-persistence, confirm-with-user]
    suggested_action: add_incident_comment
---

# Risky or impossible-travel sign-in

Use this for Entra ID Protection risk detections and Defender for Cloud Apps travel alerts. If the user confirms the
sign-in was theirs, mark the remaining steps done with a short note and post a false positive verdict.
