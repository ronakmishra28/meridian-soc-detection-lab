# Meridian SOC Detection Lab — Splunk Enterprise SIEM

**Splunk Enterprise 10.2** | **SC-200 Certified** | **CompTIA Security+** | **ISC2 CC**

A full enterprise SOC detection pipeline built from scratch in Splunk. Three endpoints, six OWASP Top 10 web application attacks, a complete insider threat kill chain, live scheduled alerts, and two formal incident reports — all built and documented end to end.

This lab covers ground my prior [Wazuh](https://github.com/ronakmishra28/wazuh-enterprise-siem-lab) and [Sentinel](https://github.com/ronakmishra28/microsoft-sentinel-enterprise-siem-lab) labs do not: **application-layer attack detection** and **insider threat investigation**.

---

![Meridian SOC Dashboard](screenshots/phase7/phase7-01-meridian-soc-dashboard.png)
*Live SOC dashboard — 6 panels, real attack data, all 3 alerts actively firing*

---

## Architecture

```
MacBook M4 Pro — Splunk Enterprise 10.2 (Central SIEM)
└── Parallels
    ├── WEB-PROD-01 · Ubuntu 22.04 · Nginx → OWASP Juice Shop (Docker, port 8080)
    ├── FIN-WKS-04  · Windows 11   · Finance workstation — insider threat target
    └── Kali Linux  · External attacker / exfiltration destination
```

| Index | Source | Purpose |
|---|---|---|
| `webapp` | WEB-PROD-01 Nginx access logs | OWASP Top 10 attack detection |
| `linux` | WEB-PROD-01 syslog + auth.log | General host visibility |
| `windows` | FIN-WKS-04 Security + PowerShell Operational | Insider threat detection |

---

## What Was Built

| Component | Details |
|---|---|
| Endpoints | 3 (Ubuntu web server, Windows 11 finance workstation, Kali attacker) |
| OWASP attacks | 6 — SQLi, credential stuffing, XSS, IDOR, path traversal, price tampering |
| Insider threat stages | 3 — file access → compression → exfiltration |
| SPL detection queries | 8 |
| Scheduled alerts | 3 (High + Critical severity) |
| Dashboard panels | 6 |
| Incident reports | 2 (IR-MER-2026-001 + IR-MER-2026-002) |

---

## Lab Phases

| Phase | What it covers | Deep dive |
|---|---|---|
| 1 — Architecture | Splunk setup, 3 UF deployments, Juice Shop on Nginx, index creation | [→ Phase 1](docs/phase1-architecture.md) |
| 2+3 — SPL & Log Anatomy | Core SPL commands, Nginx log field extraction, traffic baselining | [→ Phase 2+3](docs/phase2-3-spl-log-anatomy.md) |
| 4 — OWASP Detection | 6 attacks executed from Kali, detection queries + findings per attack | [→ Phase 4](docs/phase4-owasp-detection.md) |
| 5 — Insider Threat | 3-stage kill chain, correlated detection via `transaction` | [→ Phase 5](docs/phase5-insider-threat.md) |
| 6 — Alerts | 3 scheduled correlation alerts deployed in Splunk | [→ Phase 6](docs/phase6-alerts.md) |
| 7 — Dashboard + IR | 6-panel SOC dashboard + 2 incident reports | [→ Phase 7](docs/phase7-dashboard-incidents.md) |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|---|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application | URI pattern matching, volume threshold |
| Credential Access | T1110.004 — Credential Stuffing | Login POST count per IP per minute |
| Collection | T1005 — Data from Local System | Event ID 4663 (File System auditing) |
| Collection | T1560.001 — Archive Collected Data | Event ID 4103 (PowerShell Module Logging) |
| Exfiltration | T1048 — Exfiltration Over Alternative Protocol | Event ID 5156 (network connection audit) |
| Impact | T1565.001 — Stored Data Manipulation | Negative finding — secure design confirmed |

---

## Incident Reports

| Report | Severity | Description |
|---|---|---|
| [IR-MER-2026-001](incident-reports/IR-MER-2026-001-external-webapp-attack.md) | High | External web app attack — SQLi bypass, credential stuffing, XSS |
| [IR-MER-2026-002](incident-reports/IR-MER-2026-002-insider-data-exfiltration.md) | Critical | Insider threat — customer payment data exfiltrated to external host |

---

## Author

**Ronak Mishra**
[ronakmishra28.github.io](https://ronakmishra28.github.io) · [ronakonweb.medium.com](https://ronakonweb.medium.com) · [LinkedIn](https://www.linkedin.com/in/ronakmishra)

*Meridian Commerce Inc. is a fictional company. All data is synthetic.*
