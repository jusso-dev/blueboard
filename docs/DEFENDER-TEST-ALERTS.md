---
id: DEFENDER-TEST-ALERTS
title: Trigger a Safe Defender Test Alert (Linux, macOS & Windows)
sidebar_label: Test with a Live Defender Alert
description: Copy-paste official Microsoft Defender for Endpoint detection test scripts for Linux, macOS, and Windows so you can watch a real incident flow into blueboard, trigger autonomous agent triage, and queue a human-gated containment approval.
---

# Trigger a safe Defender test alert (Linux, macOS & Windows)

Once **blueboard** is connected to your Microsoft Defender XDR tenant (`INGEST_ENABLED=true`), the fastest way to watch the entire loop end to end — Defender alert → incident sync → agent enrichment & playbook → human approval queue — is to run Microsoft's official, non-destructive detection test on a **non-production endpoint** onboarded to Microsoft Defender for Endpoint (MDE).

> **Safety checklist before you run anything**
> - **Use a dedicated test machine** you own or manage — never a production server, domain controller, or shared jump host.
> - **Keep `BROKER_EXECUTE=false` (dry-run mode)** if you plan to click **Approve** on containment actions without actually isolating the test device.
> - **Confirm `INGEST_ENABLED=true`** and that **Setup → Incident ingest** (`/setup`) shows **OK** (blueboard polls Defender XDR every minute).

---

## Linux (Bash)

Microsoft Defender for Endpoint on Linux supports both a **fast Antivirus (EICAR) test** (fires in seconds) and Microsoft's official **EDR behavioural simulation script** (creates a richer process-tree incident in Defender XDR).

### Option A: Quick Antivirus detection test (EICAR)

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "1. Checking Defender for Endpoint sensor health..."
mdatp health --field healthy
mdatp health --field real_time_protection_enabled

echo "2. Downloading the benign EICAR standard test file..."
curl -fsSL -o /tmp/eicar.com.txt https://secure.eicar.org/eicar.com.txt || true

echo "3. Checking local MDE detections..."
sleep 3
mdatp threat list
```

> Both `healthy` and `real_time_protection_enabled` must print `true` before the test will trigger. MDE intercepts and quarantines `/tmp/eicar.com.txt` automatically.

### Option B: Full EDR behavioural alert (official Microsoft Linux DIY script)

If you want a behavioural **Endpoint Detection and Response (EDR)** alert with process evidence (rather than an auto-remediated AV file alert), run Microsoft's official Linux EDR DIY simulation:

```bash
#!/usr/bin/env bash
set -euo pipefail

mkdir -p /tmp/mde-edr-test && cd /tmp/mde-edr-test
curl -fsSL -o MDE-Linux-EDR-DIY.zip https://aka.ms/MDE-Linux-EDR-DIY
unzip -o MDE-Linux-EDR-DIY.zip
chmod +x ./mde_linux_edr_diy.sh
./mde_linux_edr_diy.sh
```

**Cleanup (Linux):** `rm -rf /tmp/mde-edr-test /tmp/eicar.com.txt` (MDE automatically quarantines the EICAR file).

---

## macOS (Terminal / zsh)

### Option A: Quick Antivirus detection test (EICAR)

```zsh
#!/usr/bin/env zsh
set -euo pipefail

echo "1. Checking Defender for Endpoint sensor health..."
mdatp health --field healthy
mdatp health --field real_time_protection_enabled

echo "2. Downloading the benign EICAR standard test file..."
curl -fsSL -o ~/Downloads/eicar.com.txt https://secure.eicar.org/eicar.com.txt || true

echo "3. Checking local MDE detections..."
sleep 3
mdatp threat list
```

> Both `healthy` and `real_time_protection_enabled` should return `true`. Defender immediately quarantines `~/Downloads/eicar.com.txt` and reports the detection to Microsoft Defender XDR.

### Option B: Full EDR behavioural alert (official Microsoft macOS DIY package)

For a behavioural EDR alert on macOS:

1. In the **Microsoft Defender portal** (`https://security.microsoft.com`), go to **Settings → Endpoints → Device management → Onboarding**, select **macOS**, and download Microsoft's official **`MDATP MacOS DIY.zip`** detection test package.
2. Unzip `MDATP MacOS DIY.zip` in `~/Downloads`, right-click **MDATP MacOS DIY → Open** (to approve running the unsigned simulation script via Gatekeeper), and confirm the prompt.
3. Within 5–10 minutes, an EDR test alert appears in Defender XDR and syncs to blueboard.

**Cleanup (macOS):** `rm -f ~/Downloads/eicar.com.txt` and remove the extracted `MDATP MacOS DIY` folder once the alert has synced.

---

## Windows (PowerShell / Command Prompt)

Microsoft's official Windows MDE onboarding verification command simulates a suspicious PowerShell download cradle targeting loopback (`http://127.0.0.1/1.exe`). Nothing is downloaded from the internet and no executable runs, yet MDE raises an EDR alert (*Suspicious PowerShell commandline* / *EDR test alert*) with rich process-tree evidence.

### Option A: Official Microsoft EDR detection test (recommended)

Open **PowerShell** (or **Command Prompt**) **as Administrator** on your onboarded Windows test device and run:

```powershell
# 1. Verify the Defender for Endpoint sensor (Sense) is running
Get-Service Sense | Select-Object Name, Status
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled

# 2. Create the Microsoft test directory
New-Item -ItemType Directory -Path 'C:\test-MDATP-test' -Force | Out-Null

# 3. Trigger Microsoft's official benign MDE EDR test (loopback only — downloads nothing)
cmd.exe /c "powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden `$ErrorActionPreference='silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\test-MDATP-test\invoice.exe');Start-Process 'C:\test-MDATP-test\invoice.exe'"
```

Or directly from an elevated **Command Prompt (`cmd.exe`)**:

```cmd
mkdir C:\test-MDATP-test
powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference='silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\test-MDATP-test\invoice.exe');Start-Process 'C:\test-MDATP-test\invoice.exe'
```

### Option B: Quick Antivirus detection test (EICAR)

```powershell
Invoke-WebRequest -Uri 'https://secure.eicar.org/eicar.com.txt' -OutFile "$env:TEMP\eicar.com.txt"
Get-MpThreatDetection | Select-Object -First 3 ThreatID, Resources, InitialDetectionTime
```

**Cleanup (Windows):** `Remove-Item -Path 'C:\test-MDATP-test' -Recurse -Force -ErrorAction SilentlyContinue`

---

## What you'll see in blueboard

| Time | What happens | Where to look |
|---|---|---|
| **0–2 min (AV) / 5–10 min (EDR)** | Microsoft Defender for Endpoint raises the test alert and creates or updates a Defender XDR incident. | `https://security.microsoft.com` → **Incidents & alerts** |
| **+1 min** | blueboard's `ingest-incidents` timer syncs the incident automatically (or trigger instant sync via the [Sentinel Automation Rule](./admin/deployment-guide.md#6-sentinel-automation-rule-real-time-sync-connector) or `sync_incident`). | **Queue** (`/`) and **`#incidents`** |
| **+1–2 min** | Connected agents (e.g., `@enrichment-agent`) claim the incident, call `recall_memory`, `lookup_entity`, and `run_hunting_query` (`DeviceProcessEvents` / `DeviceFileEvents`), and post a structured `finding`, `ioc`, and `verdict` in the thread. | **Incident workspace** (`/incidents/<id>`) |
| **+2 min** | If the agent proposes containment (such as `run_av_scan`, `collect_investigation_package`, or `isolate_device`), `PolicyEngine` validates the target against incident evidence and protected lists, then queues it for an independent human approver. | **Approvals** (`/approvals`) |
| **On approval** | A human with `Board.Approve` reviews the parameters and approves. With `BROKER_EXECUTE=false`, blueboard posts a **dry-run** `action_result` and writes the full trace to `audit_log` without touching your endpoint. | **Incident thread** & **Admin → Audit log** |

When you finish testing, close the incident in Microsoft Defender XDR as **False positive → Security testing / Penetration testing** (or **Informational, expected activity**).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Alert appears in `mdatp threat list` / `Get-MpThreatDetection` locally, but not in Defender XDR | Sensor is not onboarded to the tenant or cannot reach MDE cloud telemetry endpoints | Run `mdatp connectivity test` (Linux/macOS) or `Get-Service Sense` + MDE Client Analyzer (Windows). |
| Incident appears in `security.microsoft.com`, but not in blueboard after 2 minutes | `INGEST_ENABLED` is off, or the board's Managed Identity lacks `SecurityIncident.Read.All` / `SecurityAlert.Read.All` | Open **`/setup`** as an admin and check **Incident ingest** and **Read permissions**. |
| Incident synced to `#incidents`, but no agent replied | No MCP agent is running or subscribed to `#incidents`, or the agent lacks `Board.Post` / `Board.Hunt` | Check **Admin → Participants** (`/admin/participants`) to verify your agent's last-seen timestamp and roles. See [Connecting AI Agents](./AGENTS.md). |
| Agent proposed `isolate_device` and policy rejected it | The test hostname is listed in `protected_devices`, or `isolate_device` is disabled in `policy.json` | Inspect **Policy** (`/policy`) and test the parameters in the Policy Simulator. |
