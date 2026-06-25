# Phase 7 — Dashboard & Incident Reports

---

## Meridian SOC Dashboard

Six panels displaying live data from the attacks run in Phase 4 and 5. The dashboard is designed as a Tier 1 analyst's starting point — a single view that immediately surfaces whether any of the three protected assets (web platform, Finance workstation, authentication endpoint) have active anomalies.

![Meridian SOC Dashboard — 6 live panels, real attack data, all 3 alerts firing](../screenshots/phase7/phase7-01-meridian-soc-dashboard.png)

**Webapp Status Code Distribution (top left)** — HTTP status codes over time. The spike at 07:00–08:00 is 1,400+ `401 Unauthorized` responses from the credential stuffing attack — visible as an unmistakable deviation from the flat baseline that preceded it.

**Meridian Alert Activity (top right)** — Live alert execution log showing all three scheduled detections firing on their cron schedules with `status: success`. A blank panel here would indicate a detection pipeline failure worth investigating.

**Top Source IPs Against Login Endpoint (middle left)** — After applying the tuning fix from Phase 6, `10.0.0.31` shows 4 legitimate login attempts. The unfiltered view showed `10.0.0.100` (Kali) at 1,440+ — the most obvious signal on the dashboard.

**CustomerExports File Access by Account (middle right)** — `ronakmishra` with 21 access events against the sensitive payment data directory. A Finance account accessing a file 21 times in a session is an anomaly that warrants immediate investigation regardless of whether it's technically authorized access.

**Injection Attempts Over Time (bottom left)** — The XSS and path traversal attempts from Phase 4 produce a small, sharp spike. Low volume but against a zero baseline — unambiguous as deliberate probing rather than incidental traffic.

**Login Success vs Failure Rate (bottom right)** — The credential stuffing pattern rendered visually: sustained mass 401 failures followed by a single 200 success. This is the characteristic signature of an attacker working through a password list.

---

## Incident Reports

### IR-MER-2026-001 — External Web Application Attack
**Severity: High**

Covers the Phase 4 external attack chain. The report documents the full timeline, which detections fired and why, and critically — what wasn't detectable and why not. The two detection gaps (Nginx body logging limitation for SQLi, URL fragment blind spot for DOM XSS) are formally documented with specific remediation recommendations (WAF deployment, CSP headers, application-level logging). Business impact section quantifies the risk: admin account compromise means full access to all customer records on the platform.

→ [Read IR-MER-2026-001](../incident-reports/IR-MER-2026-001-external-webapp-attack.md)

### IR-MER-2026-002 — Insider Threat Data Exfiltration
**Severity: Critical**

Covers the Phase 5 kill chain. The report documents the technical finding about PowerShell cmdlets bypassing 4688, the three default-disabled audit subcategories required for detection, and the business impact framing — the exfiltrated data (customer ID, name, partial card number, transaction amount) falls under PCI DSS scope, making this a potential mandatory breach notification event depending on full card number exposure. Recommendations cover DLP controls, outbound port restrictions on Finance workstations, and a least-privilege review of CustomerExports access.

→ [Read IR-MER-2026-002](../incident-reports/IR-MER-2026-002-insider-data-exfiltration.md)

---

← [Phase 6](phase6-alerts.md) · [Back to README](../README.md)
