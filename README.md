# Meridian SOC Detection Lab — Splunk Enterprise SIEM

**Splunk Enterprise 10.2** · **SC-200 Certified** · **CompTIA Security+** · **ISC2 CC**

---

## Overview

This lab simulates a complete enterprise SOC monitoring environment built from scratch for a fictional mid-size e-commerce company, **Meridian Commerce Inc.** Splunk Enterprise is deployed as the central SIEM, with Universal Forwarders on three endpoints shipping logs across two distinct threat scenarios:

- **External web application attacks** — six OWASP Top 10 techniques executed against the company's customer-facing platform, detected and investigated through Nginx access logs
- **Insider threat data exfiltration** — a Finance workstation account accessing, staging, and exfiltrating customer payment data, detected through a three-stage correlated kill chain

Every detection query was written from scratch, every attack was executed manually, and every finding — including two attacks that were successfully blocked — is documented with the same rigor as a successful exploit. This lab deliberately covers ground my prior [Wazuh](https://github.com/ronakmishra28/wazuh-enterprise-siem-lab) and [Sentinel](https://github.com/ronakmishra28/microsoft-sentinel-enterprise-siem-lab) labs do not: application-layer detection and insider threat investigation.

---

## Architecture

```
MacBook M4 Pro — Splunk Enterprise 10.2 (Central SIEM — indexer + search head)
└── Parallels Desktop
    ├── WEB-PROD-01 · Ubuntu 22.04 (10.0.0.33)
    │     OWASP Juice Shop (Docker) fronted by Nginx reverse proxy
    │     Represents Meridian's customer-facing e-commerce platform
    │     Universal Forwarder → webapp index (Nginx logs) + linux index
    │
    ├── FIN-WKS-04 · Windows 11 (10.0.0.32)
    │     Finance department workstation with access to customer payment data
    │     Insider threat target in Phase 5
    │     Universal Forwarder → windows index
    │
    └── Kali Linux (10.0.0.100)
          External attacker (Phase 4) and exfiltration destination (Phase 5)
          Not monitored — attacker machines are never inside the SOC's visibility
```

| Index | Source | Log Type |
|---|---|---|
| `webapp` | WEB-PROD-01 Nginx | HTTP access logs — all OWASP detections built on this |
| `linux` | WEB-PROD-01 | syslog + auth.log — general host visibility |
| `windows` | FIN-WKS-04 | Security Events (4663, 5156) + PowerShell Operational (4103) |

---

## What Was Built

| Component | Details |
|---|---|
| Endpoints monitored | 3 — Ubuntu web server, Windows 11 Finance workstation, Kali attacker |
| Splunk indexes | 3 custom indexes (webapp, linux, windows) |
| OWASP attacks simulated | 6 — SQLi, credential stuffing, DOM XSS, IDOR, path traversal, price tampering |
| Insider threat stages | 3 — file access (Event 4663) → compression (Event 4103) → exfiltration (Event 5156) |
| SPL detection queries | 8 written from scratch |
| Scheduled alerts | 3 — High and Critical severity, running every 5-10 minutes |
| SOC dashboard panels | 6 live panels fed by real attack data |
| Incident reports | 2 — IR-MER-2026-001 (external attack) + IR-MER-2026-002 (insider threat) |

---

## SOC Dashboard

![Meridian SOC Dashboard](screenshots/phase7/phase7-01-meridian-soc-dashboard.png)

The dashboard surfaces six panels of live data: HTTP status code anomalies showing the credential stuffing spike, top attacking source IPs, injection attempt timeline, login failure/success ratio showing the brute-force-then-crack pattern, CustomerExports file access by account (21 events from `ronakmishra` — the insider threat signal), and the live alert execution log confirming all three scheduled detections running successfully.

---

## Phase 4 — OWASP Top 10 Attack Detection

| Attack | OWASP | MITRE | Outcome | Detection Method |
|---|---|---|---|---|
| SQL Injection — Login Bypass | A03 | T1190 | Admin account fully bypassed | Behavioral — POST body not logged by Nginx (detection gap documented) |
| Credential Stuffing | A07 | T1110.004 | Admin password cracked in 3/8 attempts | Volume threshold — >5 POSTs/IP/minute |
| DOM-Based XSS | A03 | T1190 | JavaScript executed in victim browser | Fragment-based delivery — invisible to server logs (detection gap documented) |
| IDOR — Basket Enumeration | A01 | T1190 | 3 other users' baskets accessed | Multiple distinct basket IDs from single source IP |
| Path Traversal | A05 | T1190 | Blocked at two separate layers | Encoded traversal pattern in URI |
| Price Tampering | A04 | T1565.001 | Not exploitable — server-side validation held | Negative finding — secure design confirmed |

Two detection gaps are identified and formally documented: Nginx not logging POST body content (affects SQLi) and URL fragments never reaching the server (affects DOM XSS). These are genuine architectural blind spots relevant to any organization running a standard Nginx stack.

→ [Full Phase 4 documentation](docs/phase4-owasp-detection.md)

---

## Phase 5 — Insider Threat & Data Exfiltration (Centerpiece)

A Finance account on FIN-WKS-04 reads `C:\CustomerExports\payments_export.csv`, compresses it into an archive, and exfiltrates it to an external host via curl on port 4444. The attack is undetectable by perimeter controls and authentication monitoring — it uses a valid account with legitimate standing access.

Detection required explicitly enabling three Windows audit subcategories disabled by default:

| Stage | Action | Event ID | Audit Subcategory |
|---|---|---|---|
| 1 — File Access | Read `payments_export.csv` | 4663 | File System (+ SACL on folder) |
| 2 — Compression | `Compress-Archive` to Desktop | 4103 | PowerShell Module Logging |
| 3 — Exfiltration | `curl.exe` POST to Kali:4444 | 5156 | Filtering Platform Connection |

All three stages correlated into one incident using `transaction`:

```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*")
    OR (EventCode=4103 _raw="*CompressFilesHelper*")
    OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
| table _time, host, eventcount, duration
```

Result: **27 raw events correlated into 1 incident spanning 25 minutes on FIN-WKS-04.**

Key technical finding: `Compress-Archive` does not trigger Event ID 4688 (Process Creation) because native PowerShell cmdlets run inside the existing PowerShell engine — no new process is spawned. Detection required PowerShell Module Logging (Event ID 4103), which captures full parameter bindings including exact source and destination paths.

→ [Full Phase 5 documentation](docs/phase5-insider-threat.md)

---

## Alerts

| Alert | Severity | Schedule | Detection Logic |
|---|---|---|---|
| Meridian - Brute Force Login Detected | High | `*/5 * * * *` | >5 login POSTs from single IP per 1-minute window |
| Meridian - Web Application Injection Attempt Detected | High | `*/5 * * * *` | Injection syntax in URI, excluding static JS files |
| Meridian - Insider Threat Data Exfiltration Chain | Critical | `*/10 * * * *` | All 3 kill chain stages on same host within 30 minutes |

→ [Full Phase 6 documentation](docs/phase6-alerts.md)

---

## Key Technical Findings

**1. Nginx access logs do not capture POST body content.**
SQL injection delivered via JSON body is completely invisible to standard web server logging. Detection requires a WAF with payload inspection or application-level request logging — a real gap in most default Nginx deployments.

**2. DOM XSS via URL fragment never reaches the server.**
URL fragments (`#/search?q=<payload>`) are stripped by the browser before the HTTP request is made. No server-side logging configuration catches this. Requires Content Security Policy headers or client-side monitoring.

**3. Native PowerShell cmdlets do not trigger Event ID 4688.**
`Compress-Archive` and other built-in cmdlets run inside the PowerShell engine — they don't spawn child processes. Any detection relying solely on process creation auditing has a blind spot against PowerShell-native staging techniques.

**4. Three critical audit subcategories are disabled by default on Windows 11.**
File System (4663), PowerShell Module Logging (4103), and Filtering Platform Connection (5156) must all be explicitly enabled. A default workstation provides almost zero insider threat telemetry without deliberate hardening.

**5. The `transaction` command turns a 27-event noise stream into one actionable alert.**
Correlating file access, compression, and exfiltration by host within a 30-minute window produces one alert per incident instead of three separate detections — dramatically reducing false positive noise and analyst fatigue.

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|---|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application | URI pattern matching, volume threshold |
| Credential Access | T1110.004 — Credential Stuffing | Login POST rate per source IP |
| Collection | T1005 — Data from Local System | Event ID 4663 |
| Collection | T1560.001 — Archive Collected Data | Event ID 4103 |
| Exfiltration | T1048 — Exfiltration Over Alternative Protocol | Event ID 5156 |
| Impact | T1565.001 — Stored Data Manipulation | Negative finding — server-side validation confirmed |

---

## Incident Reports

| Report | Severity | Summary |
|---|---|---|
| [IR-MER-2026-001](incident-reports/IR-MER-2026-001-external-webapp-attack.md) | High | External web application attack — SQLi admin bypass, credential stuffing, XSS — two detection gaps formally documented |
| [IR-MER-2026-002](incident-reports/IR-MER-2026-002-insider-data-exfiltration.md) | Critical | Insider threat — customer payment data exfiltrated via curl — PCI-relevant data classification, breach notification analysis |

---

## Deep Dive Documentation

| Phase | Link |
|---|---|
| Phase 1 — Architecture & Log Ingestion | [docs/phase1-architecture.md](docs/phase1-architecture.md) |
| Phase 2+3 — SPL Fundamentals & Log Anatomy | [docs/phase2-3-spl-log-anatomy.md](docs/phase2-3-spl-log-anatomy.md) |
| Phase 4 — OWASP Top 10 Attack Detection | [docs/phase4-owasp-detection.md](docs/phase4-owasp-detection.md) |
| Phase 5 — Insider Threat & Data Exfiltration | [docs/phase5-insider-threat.md](docs/phase5-insider-threat.md) |
| Phase 6 — Detection Engineering & Alerts | [docs/phase6-alerts.md](docs/phase6-alerts.md) |
| Phase 7 — Dashboard & Incident Reports | [docs/phase7-dashboard-incidents.md](docs/phase7-dashboard-incidents.md) |

---

## Author

**Ronak Mishra** · [ronakmishra28.github.io](https://ronakmishra28.github.io) · [ronakonweb.medium.com](https://ronakonweb.medium.com) · [LinkedIn](https://www.linkedin.com/in/ronakmishra)

*Meridian Commerce Inc. is a fictional company. All data is synthetic.*
