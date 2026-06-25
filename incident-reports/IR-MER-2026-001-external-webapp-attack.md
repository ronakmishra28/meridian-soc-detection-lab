# Incident Report: IR-MER-2026-001
## External Web Application Attack — Meridian Commerce Customer Platform

---

**Date of Report:** June 19, 2026
**Analyst:** Ronak Mishra, SOC Analyst (Meridian Commerce SOC)
**Severity:** High
**Status:** Resolved / Detections Deployed
**Affected Asset:** WEB-PROD-01 (customer-facing e-commerce platform, Juice Shop application stack)

---

## 1. Executive Summary

Between approximately 07:30 and 08:04 on June 19, 2026, an external source (10.0.0.100) conducted a series of attacks against Meridian Commerce's customer-facing web platform, WEB-PROD-01. Three distinct attack techniques were identified: SQL injection against the authentication endpoint resulting in a full administrative account bypass, credential stuffing against the same login endpoint resulting in a successful compromise of the admin account, and a DOM-based cross-site scripting (XSS) payload confirmed executable in a victim browser session.

The SQL injection and credential stuffing attacks both resulted in successful compromise of the platform's administrative account. Had this occurred against a production system, the attacker would have gained full administrative access to the platform, including visibility into customer order history and account data.

---

## 2. Timeline of Events

| Time (UTC-4) | Event | Source |
|---|---|---|
| 07:30:24 | Baseline login testing observed from internal IP 10.0.0.31 | WEB-PROD-01 Nginx logs |
| 07:32:31 | Legitimate successful login from 10.0.0.31 | WEB-PROD-01 Nginx logs |
| ~07:35 | SQL injection payload (`' OR 1=1--`) submitted to `/rest/user/login`, returned valid admin JWT token | Direct observation (curl), confirmed via Splunk |
| 07:44:52 | First login attempt from external IP 10.0.0.100 (failed) | WEB-PROD-01 Nginx logs |
| 07:45:49 | Successful login (HTTP 200) from 10.0.0.100 to `/rest/user/login` | WEB-PROD-01 Nginx logs, `index=webapp` |
| 07:56–07:57 | Credential stuffing attack executed (8 password attempts against admin@juice-sh.op); password `admin123` succeeded on 3rd attempt | Kali attacker terminal, confirmed in `index=webapp` |
| 08:02–08:04 | XSS payload (`<iframe src="javascript:alert(...)">`) submitted via search parameter; confirmed executing in browser via DOM rendering | Browser observation, partially visible in `index=webapp` (API-layer attempts only) |

---

## 3. Attack Details

### 3.1 SQL Injection — Authentication Bypass
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) | **OWASP:** A03:2021 Injection

A malformed email field (`' OR 1=1--`) submitted to the `/rest/user/login` REST endpoint returned a valid JWT authentication token for the platform's administrator account (`admin@juice-sh.op`), without knowledge of the actual administrator password.

**Detection limitation identified:** Nginx access logs (`access_combined` format) capture only the request line and headers — not the POST body. Because the injection payload was delivered in the JSON request body, it is **not visible in standard web server access logs**. Detection of this specific technique from log data alone was not possible; the attack was confirmed only through direct observation of the attacker-side request and response. This represents a genuine detection gap that would require either a Web Application Firewall with payload inspection, or application-level request logging, to close in a production environment.

### 3.2 Credential Stuffing / Brute Force
**MITRE ATT&CK:** T1110.004 (Credential Stuffing) | **OWASP:** A07:2021 Identification and Authentication Failures

Eight password attempts were made against the admin account from external IP 10.0.0.100 within a 90-second window. The weak/default password `admin123` succeeded on the third attempt, demonstrating no account lockout or rate-limiting control was in place on the authentication endpoint.

**Detection:** Successfully detected via Splunk by counting POST requests to the login endpoint grouped by source IP within a 1-minute time bucket. A scheduled alert (`Meridian - Brute Force Login Detected`) has been deployed, triggering on more than 5 attempts from a single IP per minute, running every 5 minutes.

### 3.3 DOM-Based Cross-Site Scripting
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) | **OWASP:** A03:2021 Injection

A payload (`<iframe src="javascript:alert('xss')">`) submitted via the `q` search parameter executed arbitrary JavaScript when rendered client-side, confirmed by a triggered browser alert dialog. This was independently validated by the Juice Shop application's own internal challenge-tracking system, which logged this as a solved "DOM XSS" challenge.

**Detection limitation identified:** Because this payload was delivered via the URL fragment (`#/search?q=...`), it was never transmitted to the web server — browsers do not send URL fragments in HTTP requests. This means the attack is **entirely invisible to server-side log analysis**, regardless of logging configuration. A secondary test of the same payload sent directly to the underlying `/rest/products/search` API endpoint (bypassing the fragment-based route) was successfully detected in Splunk by pattern-matching for injection syntax in the URI, distinguished further by a non-browser user agent (`curl/8.14.1`) attached to the request.

---

## 4. Detection Coverage Summary

| Technique | Detected via Logs? | Detection Method | Alert Deployed |
|---|---|---|---|
| SQL Injection (login bypass) | No (body not logged) | Manual/direct observation only | No — requires WAF or app-level logging |
| Credential Stuffing | Yes | Volume threshold by source IP | Yes — `Meridian - Brute Force Login Detected` |
| DOM XSS (fragment-based) | No (never reaches server) | Browser-side observation only | No — requires client-side/CSP monitoring |
| XSS via direct API call | Yes | Payload pattern + anomalous user agent | Yes — `Meridian - Web Application Injection Attempt Detected` |

---

## 5. Business Impact Assessment

If this attack chain had succeeded against a live production environment, the consequences would include:

- **Full administrative access** to the platform via either the SQLi bypass or the cracked admin password, exposing all customer accounts, order history, and platform configuration.
- **No commercial impact was realized** in this lab environment, as WEB-PROD-01 is an isolated test asset with no real customer data.
- **In production, this would meet the threshold for a reportable security incident**, given potential exposure of customer personal data, and could trigger breach notification obligations depending on jurisdiction and data classification.

---

## 6. Recommendations

1. **Enforce strong password policy and account lockout** on the authentication endpoint to eliminate the credential stuffing path entirely.
2. **Deploy a Web Application Firewall (WAF) with request body inspection** in front of WEB-PROD-01 to close the SQL injection detection gap identified in Section 3.1.
3. **Implement Content Security Policy (CSP) headers** to mitigate DOM-based XSS regardless of server-side log visibility.
4. **Enable application-level request logging** (beyond what Nginx provides) for any endpoint handling authentication or sensitive data submission.
5. **Tune the brute force alert** to exclude any legitimate automated health-check or service account traffic, based on the false-positive volume anomaly observed during alert testing (see Phase 6 tuning notes).

---

## 7. Detections Deployed as a Result of This Incident

- `Meridian - Brute Force Login Detected` (High severity, runs every 5 minutes)
- `Meridian - Web Application Injection Attempt Detected` (High severity, runs every 5 minutes)

---

*End of Report — IR-MER-2026-001*
