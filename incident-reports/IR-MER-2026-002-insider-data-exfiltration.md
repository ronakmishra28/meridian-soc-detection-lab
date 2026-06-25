# Incident Report: IR-MER-2026-002
## Insider Threat — Unauthorized Customer Data Access and Exfiltration

---

**Date of Report:** June 19, 2026
**Analyst:** Ronak Mishra, SOC Analyst (Meridian Commerce SOC)
**Severity:** Critical
**Status:** Resolved / Detections Deployed
**Affected Asset:** FIN-WKS-04 (Finance department workstation)
**Affected Account:** ronakmishra (local account, Finance department)

---

## 1. Executive Summary

On June 19, 2026, between approximately 08:21 and 08:46, the Finance department account on FIN-WKS-04 was observed accessing a directory containing customer payment data (`C:\CustomerExports`) outside the scope of routine activity, compressing the contents into an archive, and transferring that archive to an external host via an unencrypted HTTP POST request on a non-standard port. The full sequence — file access, compression, and exfiltration — was reconstructed and correlated into a single incident using Splunk's `transaction` command, spanning approximately 25 minutes.

This incident represents a textbook insider data exfiltration pattern: a user with legitimate standing access to sensitive data used that access outside its intended purpose. Because the account involved had valid credentials and authorized access to the file share, this activity would **not** have been flagged by any perimeter or authentication-based control — it was detectable only through object access auditing, process/command-line logging, and network connection auditing, all of which require explicit configuration beyond Windows default settings.

---

## 2. Timeline of Events (Correlated Attack Chain)

| Time (UTC-4) | Stage | Event | Detection Source |
|---|---|---|---|
| 08:21:22 | 1 — File Access | `payments_export.csv` read via PowerShell (`Get-Content`) | Event ID 4663 |
| 08:28–08:34 | 1 — File Access (repeated) | Multiple additional reads of the CustomerExports directory | Event ID 4663 |
| 08:28:41 / 08:31:45 | 2 — Compression | `Compress-Archive` invoked, packaging `payments_export.csv` into `export.zip` on user's Desktop | Event ID 4103 (PowerShell Module Logging) |
| 08:46:28 | 3 — Exfiltration | `curl.exe` initiated outbound connection from FIN-WKS-04 (10.0.0.32) to external host 10.0.0.100 on port 4444; archive transmitted | Event ID 5156 (Windows Filtering Platform) |
| 08:46:28 | — | Listener on destination host confirms full receipt of 431-byte archive | Direct observation (attacker-side listener) |

**Total transaction duration:** ~1,505 seconds (~25 minutes) on a single host, automatically correlated via Splunk `transaction` command grouping all three stages.

---

## 3. Technical Findings

### 3.1 Stage 1 — Unauthorized File Access
**MITRE ATT&CK:** T1005 (Data from Local System)

The account accessed `C:\CustomerExports\payments_export.csv`, a file containing customer ID, name, partial card number, and transaction amount fields. Detection required enabling the **File System** audit subcategory (`auditpol /set /subcategory:"File System"`) and configuring a System Access Control List (SACL) on the target directory — neither is enabled by default on a standard Windows 11 installation.

### 3.2 Stage 2 — Data Staging via Compression
**MITRE ATT&CK:** T1560.001 (Archive Collected Data)

The native PowerShell cmdlet `Compress-Archive` was used to package the sensitive file into a zip archive. A significant technical finding emerged during investigation: **native PowerShell cmdlets do not trigger Event ID 4688 (Process Creation)**, because cmdlets execute within the existing PowerShell engine process rather than spawning a new child process. This is a meaningful blind spot — an analyst relying solely on process creation auditing would miss this stage entirely.

Detection required enabling **PowerShell Module Logging** (Event ID 4103) via registry policy (`EnableScriptBlockLogging`), and forwarding the `Microsoft-Windows-PowerShell/Operational` event log channel, which is not collected by default Windows Event Forwarding or standard Splunk Universal Forwarder configurations. The resulting log entry captured the full parameter binding for the operation, including exact source file path, destination path, and compression settings.

### 3.3 Stage 3 — Exfiltration
**MITRE ATT&CK:** T1048 (Exfiltration Over Alternative Protocol)

The compressed archive was transmitted via `curl.exe` using an unencrypted HTTP POST request to an external IP address on port 4444 — a non-standard port commonly associated with command-and-control or exfiltration channels in real-world intrusions. Detection required enabling the **Filtering Platform Connection** audit subcategory, which logs every permitted network connection on the host and is disabled by default due to its high volume in production environments.

### 3.4 Correlated Detection
All three stages were combined into a single SPL query using the `transaction` command, grouping events by host within a 30-minute window:

```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*") OR (EventCode=4103 _raw="*CompressFilesHelper*") OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
```

This single query automatically reconstructed the full incident from 27 individual raw events into one correlated transaction, demonstrating the practical value of correlation logic over isolated single-event alerting.

---

## 4. Detection Coverage Summary

| Stage | Detected via Logs? | Required Configuration | Alert Deployed |
|---|---|---|---|
| File Access | Yes | File System auditing + SACL | Part of correlation alert |
| Compression | Yes | PowerShell Module Logging (4103) | Part of correlation alert |
| Exfiltration | Yes | Filtering Platform Connection auditing (5156) | Part of correlation alert |
| Full Chain (correlated) | Yes | All of the above + `transaction` correlation | `Meridian - Insider Threat Data Exfiltration Chain` |

---

## 5. Business and Regulatory Impact Assessment

- **Data classification:** The accessed file contained customer payment-related fields (customer ID, name, partial card number, transaction amount) — classified as sensitive financial data under typical data governance frameworks.
- **In a production context**, exfiltration of this dataset would likely meet the threshold for a reportable data breach, potentially triggering disclosure obligations under applicable privacy and financial data protection regulations (e.g., PCI DSS for payment card data, depending on full card number exposure).
- **No real customer data was exposed** in this lab environment; the dataset used was synthetic test data created specifically for this exercise.
- **The detection gaps identified** (default-disabled audit policies across three separate subcategories) represent a realistic finding that would apply to most unhardened Windows environments — this is a meaningful, generalizable insight beyond the specific lab scenario.

---

## 6. Recommendations

1. **Enable File System, Process Creation, PowerShell Module Logging, and Filtering Platform Connection auditing** as a security baseline on any workstation with access to sensitive data repositories — none of these are enabled by default.
2. **Apply Data Loss Prevention (DLP) controls** on endpoints with access to customer financial data, specifically monitoring for compression operations followed by outbound network activity.
3. **Restrict outbound connections on non-standard ports** from workstations that do not have a legitimate business need for such traffic; FIN-WKS-04 should not require outbound access on port 4444 under any normal workflow.
4. **Implement the `transaction`-based correlation alert** (already deployed: `Meridian - Insider Threat Data Exfiltration Chain`) as a standing detection, tuned to exclude known legitimate backup or sync processes that may also touch the CustomerExports directory.
5. **Review file share permissions** for `C:\CustomerExports` to ensure access is limited to the minimum necessary personnel (principle of least privilege).

---

## 7. Detections Deployed as a Result of This Incident

- `Meridian - Insider Threat Data Exfiltration Chain` (Critical severity, runs every 10 minutes, correlates file access + compression + exfiltration into a single alert)

---

*End of Report — IR-MER-2026-002*
