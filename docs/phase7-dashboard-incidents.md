# Phase 7 — Dashboard & Incident Reports

## Overview
Everything built across Phases 1-6 gets surfaced in two places: a live SOC dashboard showing real-time attack data, and two formal incident reports documenting what happened, what was detected, what the business impact would be, and what needs to be fixed.

---

## Meridian SOC Dashboard

6 panels, all driven by live SPL queries against real attack data generated during the lab.

![Meridian SOC Dashboard](../screenshots/phase7/phase7-01-meridian-soc-dashboard.png)

| Panel | Query | What it shows |
|---|---|---|
| Webapp Status Code Distribution | `index=webapp \| timechart count by status` | 401 spike visible during credential stuffing attack |
| Top Source IPs Against Login Endpoint | `index=webapp uri="*login*" \| stats count by clientip` | Kali (10.0.0.100) dominates after brute force |
| Injection Attempts Over Time | URI pattern match timechart | XSS/injection spike clearly visible |
| Login Success vs Failure Rate | Login status timechart | Mass failure → single success pattern |
| CustomerExports File Access by Account | `EventCode=4663 \| stats count by Account_Name` | `ronakmishra` with 21 file access events |
| Meridian Alert Activity | Scheduler log | All 3 alerts showing `status: success` |

---

## Incident Reports

### IR-MER-2026-001 — External Web Application Attack

**Severity:** High | **Status:** Resolved

Covers the full external attack chain from Phase 4: SQL injection admin bypass, credential stuffing (admin123 cracked), and DOM-based XSS. Includes:
- Full timeline of events with timestamps
- Detection coverage table (what was caught vs what wasn't and why)
- Business impact assessment — admin access exposure, customer data risk
- Two detection gaps documented: Nginx body logging limitation, DOM XSS fragment blind spot
- Recommendations: WAF deployment, strong password policy, CSP headers

→ [Read IR-MER-2026-001](../incident-reports/IR-MER-2026-001-external-webapp-attack.md)

---

### IR-MER-2026-002 — Insider Threat Data Exfiltration

**Severity:** Critical | **Status:** Resolved

Covers the full insider threat kill chain from Phase 5: unauthorized file access, compression staging, and exfiltration via curl to an external host. Includes:
- Stage-by-stage timeline with event IDs and timestamps
- Technical finding: PowerShell cmdlets bypass Event ID 4688
- Detection coverage table (all three stages detected, but required non-default audit configuration)
- Business impact: customer payment data (PCI-relevant), potential breach notification obligation
- Recommendations: DLP controls, outbound port restriction, principle of least privilege on file shares

→ [Read IR-MER-2026-002](../incident-reports/IR-MER-2026-002-insider-data-exfiltration.md)

---

← [Phase 6](phase6-alerts.md) | [Back to README](../README.md)
