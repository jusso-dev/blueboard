---
id: bec-aitm-token-theft
title: Business Email Compromise & AiTM token theft
priority: 20
match:
  titles: ["inbox rule", "forwarding rule", "business email compromise", "adversary-in-the-middle", "AiTM", "stolen session cookie", "session hijack"]
  techniques: ["T1539", "T1114", "T1564.008"]
steps:
  - id: scope-signins
    stage: triage
    title: Map suspicious sign-ins, session IDs and token replay
    detail: Query AADSignInEventsBeta / SigninLogs for the user over the last 72h. Identify anomalous IPs, ASNs, user agents, and whether a single SessionId was replayed from two locations. Post a finding with timestamps and IPs.
  - id: check-persistence
    stage: investigate
    title: Check mailbox rules, MFA methods and OAuth consents
    detail: Inspect CloudAppEvents / OfficeActivity for New-InboxRule, Set-InboxRule, UpdateInboxRules, new security info / FIDO / Authenticator registrations, and recent OAuth app grants. Post all persistence artefacts as findings.
    after: [scope-signins]
  - id: check-blast-radius
    stage: investigate
    title: Check outbound phishing, wire fraud and accessed data
    detail: Search EmailEvents for outbound emails sent by the compromised mailbox (especially replies to finance/vendor threads) and CloudAppEvents for MailItemsAccessed / SharePoint downloads.
    after: [scope-signins]
  - id: confirm-compromised
    stage: contain
    title: Mark the user compromised in Entra ID Protection
    detail: Triggers risk-based Conditional Access policies immediately. Confirm the Entra user object id from incident evidence first.
    after: [scope-signins]
    suggested_action: confirm_user_compromised
  - id: revoke-sessions
    stage: contain
    title: Revoke all refresh tokens and active sessions
    after: [scope-signins]
    suggested_action: revoke_sessions
  - id: reset-password
    stage: eradicate
    title: Force password reset and remove attacker persistence
    detail: Request reset_password, then instruct the analyst/admin to remove malicious inbox rules and any newly registered MFA methods in Entra.
    after: [revoke-sessions, check-persistence]
    suggested_action: reset_password
  - id: purge-outbound
    stage: eradicate
    title: Purge any internal phishing emails sent by the compromised mailbox
    after: [check-blast-radius]
    suggested_action: purge_email
  - id: block-infra
    stage: contain
    title: Block AiTM phishing domains, URLs and attacker IPs
    after: [scope-signins]
    suggested_action: block_indicator
  - id: record
    stage: record
    title: Post verdict, summary and update Defender / Sentinel incident
    after: [reset-password, purge-outbound, block-infra]
    suggested_action: add_incident_comment
---

# Business Email Compromise & AiTM token theft

Use this playbook when an attacker steals an Entra session cookie via an Adversary-in-the-Middle (AiTM) phishing proxy or establishes mailbox forwarding/hiding rules for Business Email Compromise (BEC).

Key principle: resetting a password alone does **not** invalidate a stolen session cookie — always pair `confirm_user_compromised` + `revoke_sessions` + `reset_password`, and check for newly registered MFA factors or OAuth apps that survive password changes.
