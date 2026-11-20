---
id: phishing
title: Phishing email
match:
  titles: ["phish", "malicious URL", "email messages containing", "user clicked"]
  techniques: ["T1566"]
steps:
  - id: scope-recipients
    stage: triage
    title: Find every recipient of the message
    detail: Search EmailEvents for the same sender, subject, network message id or URL. Post the recipient count and list as a finding.
  - id: analyse-payload
    stage: investigate
    title: Analyse the link or attachment
    detail: Check the URL, domain and attachment hashes with lookup_entity and threat intel. Post what you find as ioc messages with a verdict.
  - id: check-clicks
    stage: investigate
    title: Check who clicked or opened it
    detail: UrlClickEvents and DeviceEvents for each recipient. Post who clicked, when, and whether the click was blocked.
    after: [scope-recipients]
  - id: purge
    stage: contain
    title: Remove the message from every mailbox
    after: [scope-recipients, analyse-payload]
    suggested_action: purge_email
  - id: block-indicators
    stage: contain
    title: Block the sender domain, URLs and hashes
    after: [analyse-payload]
    suggested_action: block_indicator
  - id: secure-clickers
    stage: eradicate
    title: Revoke sessions for users who clicked
    detail: For anyone who entered credentials, also ask for a password reset.
    after: [check-clicks]
    suggested_action: revoke_sessions
  - id: record
    stage: record
    title: Post a verdict and note the outcome on the Defender incident
    after: [purge, block-indicators, secure-clickers]
    suggested_action: add_incident_comment
---

# Phishing email

Use this when Defender for Office 365 or a user report raises a phishing message. The aim is to know who got it, who
acted on it, and to remove it before anyone else does.

Steps are claimed and completed like any question. Containment steps only suggest an action: request it from the
incident when the evidence supports it, and a person approves it as usual.
