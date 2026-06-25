# Meridian SOC Detection Lab — Splunk Enterprise SIEM

A Splunk-based security operations detection lab built around a fictional company, **Meridian Commerce Inc.** — a mid-size online retailer. This lab demonstrates end-to-end SOC analyst workflows: multi-source log ingestion, SPL-based detection engineering, OWASP Top 10 web application attack detection, insider threat investigation, scheduled alerting, and incident reporting.

This is the third lab in my detection engineering series, deliberately covering ground my prior labs do not:

| Lab | Focus | Attack surface |
|---|---|---|
| [Wazuh Enterprise SIEM](https://github.com/ronakmishra28/wazuh-enterprise-siem-lab) | Endpoint detection, custom rules, MITRE mapping | Host/network layer |
| [Microsoft Sentinel Enterprise SIEM](https://github.com/ronakmishra28/microsoft-sentinel-enterprise-siem-lab) | Cloud-native SIEM, KQL, NIST IR | Infrastructure kill chain |
| **This lab** | **Application-layer detection, insider threat, SPL correlation** | **Web application + internal data exfiltration** |

---

## Lab Architecture

```
MacBook M4 Pro — Splunk Enterprise 10.2 (indexer + search head) — Meridian SOC
└── Parallels Desktop
    ├── WEB-PROD-01 (Ubuntu 22.04)
    │     Nginx reverse proxy → OWASP Juice Shop (Docker, port 8080)
    │     Meridian's customer-facing e-commerce platform
    │     Universal Forwarder → webapp + linux indexes
    │
    ├── FIN-WKS-04 (Windows 11)
    │     Finance department workstation
    │     Access to C:\CustomerExports\ (customer payment data)
    │     Universal Forwarder → windows index
    │
    └── Kali Linux
          External threat actor (Phase 4) / exfiltration destination (Phase 5)
```

### Splunk Indexes

| Index | Source | Purpose |
|---|---|---|
| `webapp` | WEB-PROD-01 Nginx access/error logs | OWASP attack detection |
| `linux` | WEB-PROD-01 syslog + auth.log | General host visibility |
| `windows` | FIN-WKS-04 Security + PowerShell Operational logs | Insider threat detection |

---

## Lab Phases

### Phase 1 — Architecture & Multi-Source Ingestion
- Splunk Enterprise with 10GB Developer License
- Universal Forwarder deployed on 3 endpoints
- OWASP Juice Shop deployed via Docker, fronted by Nginx reverse proxy
- 3 separate indexes with distinct log sources

### Phase 2+3 — SPL Fundamentals & Log Anatomy
- Core SPL commands: `stats`, `eval`, `rex`, `timechart`, `top`, `transaction`
- Nginx combined log format field extraction (`clientip`, `method`, `uri`, `status`, `bytes`, `useragent`)
- Baseline traffic profiling before attack simulation

### Phase 4 — OWASP Top 10 Attack Detection (6 attacks)

| # | Attack | OWASP | MITRE | Result | Detected via Splunk |
|---|---|---|---|---|---|
| 1 | SQL Injection — Login Bypass | A03 Injection | T1190 | Admin account bypassed | Behavioral (volume pattern — POST body not logged by Nginx) |
| 2 | Credential Stuffing | A07 Auth Failures | T1110.004 | Admin123 cracked in 3 attempts | Volume threshold by source IP |
| 3 | DOM-Based XSS | A03 Injection | T1190 | JavaScript executed in browser | Fragment-based — invisible to server logs (documented blind spot) |
| 4 | IDOR — Basket Enumeration | A01 Broken Access Control | T1190 | 3 other users' baskets accessed | Multiple distinct basket IDs from one IP |
| 5 | Path Traversal | A05 Security Misconfiguration | T1190 | Blocked by two-layer defense | Encoded traversal pattern in URI |
| 6 | Price Tampering | A04 Insecure Design | T1565.001 | Server-side price calc prevented exploit | Negative finding — secure design documented |

### Phase 5 — Insider Threat & Data Exfiltration (Centerpiece)

A legitimate Finance account on FIN-WKS-04 stages and exfiltrates customer payment data:

**Stage 1 — File Access** → Event ID 4663 (File System auditing, SACL on CustomerExports)
**Stage 2 — Compression** → Event ID 4103 (PowerShell Module Logging — `Compress-Archive` detected)
**Stage 3 — Exfiltration** → Event ID 5156 (Filtering Platform Connection — curl.exe to Kali:4444)

**Centerpiece correlation query** — all 3 stages into one incident:
```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*") OR (EventCode=4103 _raw="*CompressFilesHelper*") OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
| table _time, host, eventcount, duration
```
Result: 27 raw events correlated into 1 incident transaction spanning ~25 minutes.

**Key technical finding:** Native PowerShell cmdlets (`Compress-Archive`) do **not** trigger Event ID 4688 (Process Creation) — they execute within the existing PowerShell engine. Detection required explicitly enabling PowerShell Module Logging (Event ID 4103) via registry policy, which is disabled by default.

### Phase 6 — Detection Engineering & Alerts

Three scheduled correlation searches deployed as live Splunk alerts:

| Alert | Severity | Schedule | Trigger |
|---|---|---|---|
| Meridian - Brute Force Login Detected | High | Every 5 min | >5 login attempts per IP per minute |
| Meridian - Web Application Injection Attempt Detected | High | Every 5 min | Injection syntax in URI |
| Meridian - Insider Threat Data Exfiltration Chain | Critical | Every 10 min | 3-stage correlated transaction |

### Phase 7 — Dashboard & Incident Reports

**Meridian SOC Dashboard** (6 panels):
- Webapp status code distribution over time
- Top source IPs against login endpoint
- Injection attempts over time
- Login success vs failure rate
- CustomerExports file access by account
- Meridian alert activity (live alert firing log)

**Incident Reports:**
- [IR-MER-2026-001](incident-reports/IR-MER-2026-001-external-webapp-attack.md) — External Web Application Attack
- [IR-MER-2026-002](incident-reports/IR-MER-2026-002-insider-data-exfiltration.md) — Insider Threat Data Exfiltration

---

## Key Technical Findings

These are the genuinely non-obvious findings from this lab — not things you'd get from a tutorial:

**1. Nginx access logs don't capture POST body content.**
SQL injection delivered via JSON POST body is completely invisible to standard web server logging. Detection requires a WAF with payload inspection or application-level request logging. This is a real detection gap in most default web infrastructure setups.

**2. DOM-based XSS is invisible to server-side logs.**
Payloads delivered via URL fragment (`#/search?q=<payload>`) are never sent to the server — browsers strip fragments before making HTTP requests. No amount of server-side logging catches this. Requires CSP headers or client-side monitoring.

**3. Native PowerShell cmdlets bypass Event ID 4688.**
`Compress-Archive`, `Invoke-WebRequest`, and other built-in cmdlets run inside the PowerShell engine — they don't spawn new processes. Any detection strategy relying solely on process creation auditing will miss these entirely. PowerShell Module Logging (4103) via registry policy is required.

**4. Three separate audit subcategories must be explicitly enabled for insider threat detection.**
File System (4663), PowerShell Module Logging (4103), and Filtering Platform Connection (5156) are all disabled by default on Windows 11. A fresh workstation gives you almost zero insider-threat telemetry without explicit configuration — this is a realistic gap at most organizations.

**5. The `transaction` command turns multi-stage incidents into single detections.**
Individual event-based detection of each stage (file access, compression, exfil) produces noise. Correlating them with `transaction` by host within a time window produces one alert per incident, dramatically reducing false positive volume and analyst fatigue.

---

## Repository Structure

```
meridian-soc-detection-lab/
├── README.md
├── configs/
│   ├── webprod01-inputs.conf      ← Ubuntu UF config
│   ├── finwks04-inputs.conf       ← Windows UF config
│   ├── outputs.conf               ← Forwarder → Splunk routing
│   └── nginx-juiceshop-reverse-proxy.conf
├── detections/
│   ├── phase4-sqli-login-bypass.md
│   ├── phase4-credential-stuffing.md
│   ├── phase4-xss-injection.md
│   ├── phase4-idor-basket.md
│   ├── phase4-path-traversal.md
│   └── phase5-insider-exfiltration.md
├── incident-reports/
│   ├── IR-MER-2026-001-external-webapp-attack.md
│   └── IR-MER-2026-002-insider-data-exfiltration.md
└── screenshots/
    ├── phase1/    ← Architecture & ingestion
    ├── phase2/    ← SPL fundamentals
    ├── phase3/    ← Log anatomy & baselining
    ├── phase4/    ← OWASP attack detection
    ├── phase5/    ← Insider threat kill chain
    ├── phase6/    ← Alert configuration
    └── phase7/    ← Dashboard
```

---

## Tools & Technologies

| Tool | Role |
|---|---|
| Splunk Enterprise 10.2 | Central SIEM — indexing, search, alerting, dashboards |
| Splunk Universal Forwarder 10.2.3 | Log shipping agent on all endpoints |
| OWASP Juice Shop | Target web application (intentionally vulnerable e-commerce app) |
| Docker | Juice Shop container runtime |
| Nginx 1.18 | Reverse proxy in front of Juice Shop — generates access_combined logs |
| Kali Linux | Attacker machine — Hydra, curl, custom bash scripts |
| Windows 11 | Insider threat endpoint — PowerShell, Windows Event auditing |
| Ubuntu 22.04 | Web server and Linux endpoint |
| Parallels Desktop | VM hypervisor on M4 Pro Mac |

---

## Certifications & Context

Built as part of my SOC Analyst career development alongside:
- SC-200: Microsoft Security Operations Analyst (passed May 2026)
- CompTIA Security+
- ISC2 CC

**Blog:** [ronakonweb.medium.com](https://ronakonweb.medium.com)
**Portfolio:** [ronakmishra28.github.io](https://ronakmishra28.github.io)

---

*Meridian Commerce Inc. is a fictional company created for this lab. All data used is synthetic.*
