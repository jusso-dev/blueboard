---
id: data-exfiltration-cloud
title: Cloud data exfiltration & mass download
priority: 10
match:
  titles: ["mass download", "exfiltration", "unusual file share", "anomalous download", "SharePoint download", "OneDrive download"]
  techniques: ["T1567", "T1530", "T1048"]
steps:
  - id: scope-volume
    stage: triage
    title: Quantify downloaded/shared files, sites and sensitivity labels
    detail: Query CloudAppEvents and OfficeActivity (FileDownloaded, FileSyncDownloadedFull, AnonymousLinkCreated, SharingSet) over the last 7 days. Post file counts, sites, sensitivity labels and destination IPs/devices as a finding.
  - id: verify-account-device
    stage: investigate
    title: Determine whether activity is account compromise or insider action
    detail: Compare the sign-in IP, device compliance and user-agent against the user's 30-day baseline. Check whether the device is managed in MDE and whether HR/manager context applies.
    after: [scope-volume]
  - id: check-external-transfers
    stage: investigate
    title: Check for uploads to personal cloud storage or external email forwarding
    detail: Query DeviceNetworkEvents and CloudAppEvents for transfers to personal OneDrive, Google Drive, Dropbox, MEGA, GitHub or external email recipients.
    after: [scope-volume]
  - id: tag-or-contain-device
    stage: contain
    title: Tag affected managed endpoint for investigation
    after: [verify-account-device]
    suggested_action: tag_device
  - id: contain-account
    stage: contain
    title: Revoke active sessions (or disable account if confirmed unauthorised)
    detail: If insider risk rather than compromise, confirm with Legal/HR before disabling the user account.
    after: [verify-account-device, check-external-transfers]
    suggested_action: revoke_sessions
  - id: record
    stage: record
    title: Post verdict, impacted datasets and update Defender / Sentinel incident
    after: [tag-or-contain-device, contain-account]
    suggested_action: add_incident_comment
---

# Cloud data exfiltration & mass download

Use this for Microsoft Defender for Cloud Apps, Purview Insider Risk, or Sentinel alerts detecting mass SharePoint/OneDrive downloads (`T1530`), external sharing links, or uploads to unsanctioned cloud storage (`T1567`).
