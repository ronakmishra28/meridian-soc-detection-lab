# Meridian SOC Detection Lab — Splunk Enterprise SIEM

**Splunk Enterprise 10.2** | **SC-200 Certified** | **CompTIA Security+** | **ISC2 CC**

Built a full enterprise SOC detection pipeline in Splunk from scratch — three endpoints, six OWASP Top 10 detections, an insider threat kill chain, live scheduled alerts, and two formal incident reports. This lab covers ground my prior [Wazuh](https://github.com/ronakmishra28/wazuh-enterprise-siem-lab) and [Sentinel](https://github.com/ronakmishra28/microsoft-sentinel-enterprise-siem-lab) labs do not: **application-layer attack detection** and **insider threat investigation** — areas most entry-level candidates never demonstrate.

---

![Meridian SOC Dashboard](screenshots/phase7/phase7-01-meridian-soc-dashboard.png)

---

## Architecture

```
MacBook M4 Pro — Splunk Enterprise 10.2 (Central SIEM)
└── Parallels
    ├── WEB-PROD-01 · Ubuntu 22.04 · Nginx → OWASP Juice Shop (Docker)
    ├── FIN-WKS-04  · Windows 11   · Finance workstation (insider threat target)
    └── Kali Linux  · Attacker machine / exfiltration destination
```

| Index | Source | Logs |
|---|---|---|
| `webapp` | WEB-PROD-01 Nginx | Juice Shop access + error logs (`access_combined`) |
| `linux` | WEB-PROD-01 | syslog + auth.log |
| `windows` | FIN-WKS-04 | Security Events + PowerShell Operational |

---

## What Was Built

| | |
|---|---|
| Endpoints monitored | 3 (Ubuntu, Windows 11, Kali) |
| Splunk indexes | 3 (webapp, linux, windows) |
| OWASP attacks simulated | 6 |
| Insider threat stages | 3 (file access → compression → exfiltration) |
| SPL detection queries | 8 |
| Scheduled alerts | 3 (High / Critical) |
| Dashboard panels | 6 |
| Incident reports | 2 (IR-MER-2026-001, IR-MER-2026-002) |

---

## Phase 4 — OWASP Top 10 Attack Detection

All attacks executed from Kali against WEB-PROD-01 (10.0.0.33:8080).

| Attack | OWASP | MITRE | Result | Detected |
|---|---|---|---|---|
| SQL Injection — Login Bypass | A03 | T1190 | Admin JWT token returned | Behavioral — POST body not logged by Nginx (documented gap) |
| Credential Stuffing | A07 | T1110.004 | Admin cracked in 3/8 attempts | >5 POSTs/IP/min threshold |
| DOM-Based XSS | A03 | T1190 | JS executed in browser | Fragment-based — server-side blind spot (documented) |
| IDOR — Basket Enumeration | A01 | T1190 | 3 other users' baskets accessed | Multiple basket IDs from single IP |
| Path Traversal | A05 | T1190 | Blocked at two layers | Encoded traversal pattern in URI |
| Price Tampering | A04 | T1565.001 | Not exploitable | Server-side price calculation — secure design confirmed |

![SQLi admin bypass](screenshots/phase4/phase4-02-sqli-admin-bypass-success.png)

![IDOR detection in Splunk](screenshots/phase4/phase4-13-idor-detected-splunk.png)

---

## Phase 5 — Insider Threat & Data Exfiltration

Finance account on FIN-WKS-04 accesses, compresses, and exfiltrates `C:\CustomerExports\payments_export.csv` to an external host.

| Stage | Action | MITRE | Event ID |
|---|---|---|---|
| 1 | Read customer payment CSV | T1005 | 4663 (File System auditing) |
| 2 | `Compress-Archive` to Desktop | T1560.001 | 4103 (PowerShell Module Logging) |
| 3 | `curl.exe` POST to Kali:4444 | T1048 | 5156 (Filtering Platform Connection) |

All three stages correlated into one incident using `transaction`:

```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*")
    OR (EventCode=4103 _raw="*CompressFilesHelper*")
    OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
| table _time, host, eventcount, duration
```
> 27 raw events → 1 correlated incident · ~25 minute transaction window

![Insider threat correlation](screenshots/phase5/phase5-10-transaction-correlation.png)

![Exfiltration network event](screenshots/phase5/phase5-08-event5156-network-detected.png)

---

## Phase 6 — Alerts

| Alert | Severity | Schedule |
|---|---|---|
| Meridian - Brute Force Login Detected | High | `*/5 * * * *` |
| Meridian - Web Application Injection Attempt Detected | High | `*/5 * * * *` |
| Meridian - Insider Threat Data Exfiltration Chain | Critical | `*/10 * * * *` |

![Alerts firing](screenshots/phase6/phase6-01-bruteforce-alert-saved.png)

---

## Key Findings

**1. Nginx doesn't log POST bodies.**
SQL injection via JSON body is invisible to standard web server logs. Requires WAF payload inspection or app-level logging.

**2. DOM XSS via URL fragment never reaches the server.**
Fragment-based payloads (`#/search?q=<payload>`) are stripped by the browser before the HTTP request is made — completely undetectable server-side.

**3. `Compress-Archive` doesn't trigger Event ID 4688.**
Native PowerShell cmdlets run inside the PowerShell engine — no new process, no process creation event. Requires PowerShell Module Logging (Event ID 4103) via registry policy.

**4. Three audit subcategories are disabled by default on Windows 11.**
File System (4663), PowerShell Module Logging (4103), and Filtering Platform Connection (5156) must all be explicitly enabled. A default workstation gives almost zero insider-threat telemetry.

**5. `transaction` turns a 27-event noise stream into one alert.**
Correlating file access + compression + exfiltration by host within a 30-minute window = one actionable incident instead of three separate noisy detections.

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|---|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application | URI pattern matching, volume threshold |
| Credential Access | T1110.004 — Credential Stuffing | Login POST count per IP per minute |
| Collection | T1005 — Data from Local System | Event ID 4663 |
| Collection | T1560.001 — Archive Collected Data | Event ID 4103 |
| Exfiltration | T1048 — Exfiltration Over Alternative Protocol | Event ID 5156 |
| Impact | T1565.001 — Stored Data Manipulation | Negative finding — server-side validation |

---

## Incident Reports

| Report | Severity | Summary |
|---|---|---|
| [IR-MER-2026-001](incident-reports/IR-MER-2026-001-external-webapp-attack.md) | High | External web application attack — SQLi, credential stuffing, XSS |
| [IR-MER-2026-002](incident-reports/IR-MER-2026-002-insider-data-exfiltration.md) | Critical | Insider threat — customer payment data exfiltrated via curl to external host |

---

## Detection Queries

Full detection logic in [`detections/`](detections/). Key queries:

**Credential stuffing:**
```spl
index=webapp uri="*login*" method=POST
| bucket _time span=1m
| stats count by clientip, _time
| where count > 5
```

**IDOR enumeration:**
```spl
index=webapp uri="*/rest/basket/*"
| rex field=uri "basket/(?<basket_id>\d+)"
| stats dc(basket_id) as unique_baskets by clientip
| where unique_baskets > 1
```

**Insider threat correlation:**
```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*")
    OR (EventCode=4103 _raw="*CompressFilesHelper*")
    OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
```

---

## Repo Structure

```
meridian-soc-detection-lab/
├── configs/          ← Universal Forwarder inputs.conf + outputs.conf + Nginx config
├── detections/       ← 6 detection files with SPL, MITRE mapping, tuning notes
├── incident-reports/ ← IR-MER-2026-001 + IR-MER-2026-002
└── screenshots/
    ├── phase1/       ← Architecture + log ingestion proof
    ├── phase2-3/     ← SPL queries + log anatomy
    ├── phase4/       ← 6 attacks — command + Splunk detection per attack
    ├── phase5/       ← Insider threat kill chain
    ├── phase6/       ← Alert configuration
    └── phase7/       ← SOC dashboard
```

---

## Author

**Ronak Mishra**
[ronakmishra28.github.io](https://ronakmishra28.github.io) · [ronakonweb.medium.com](https://ronakonweb.medium.com) · [LinkedIn](https://www.linkedin.com/in/ronakmishra)

*Meridian Commerce Inc. is a fictional company. All data is synthetic.*
