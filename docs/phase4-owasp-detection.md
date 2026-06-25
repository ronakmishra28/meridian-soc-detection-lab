# Phase 4 — OWASP Top 10 Attack Detection

Six attacks executed from Kali (10.0.0.100) against WEB-PROD-01 (10.0.0.33:8080). Each attack documents the technique, the result, the SPL detection query, and the honest assessment of what is and isn't detectable from standard web server logs. Two attacks were blocked — those findings are documented with equal rigor.

---

## Attack 1 — SQL Injection (Login Bypass)
**OWASP A03 · MITRE T1190**

Injecting `' OR 1=1--` into the email field causes the underlying SQL query to evaluate as always-true, bypassing authentication entirely. No knowledge of the actual admin password is required.

```bash
curl -X POST http://10.0.0.33:8080/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","password":"x"}'
```

The response returns a valid JWT for `admin@juice-sh.op` with `"role":"admin"` — full administrative access to the platform granted without credentials.

![Full admin JWT token returned — authentication bypassed with a single crafted request](../screenshots/phase4/phase4-02-sqli-admin-bypass-success.png)

**Detection query:**
```spl
index=webapp uri="*login*" method=POST
| stats count, values(status) as statuses by clientip
```

This query surfaces login attempt volume and outcome by source IP. Kali's IP (`10.0.0.100`) appears with a `200` response — but the query cannot distinguish a legitimate login from an SQLi bypass because the payload was in the POST body.

![Login attempts in Splunk — Kali IP visible with successful status, but payload not captured](../screenshots/phase4/phase4-03-sqli-detected-in-splunk.png)

**Finding:** Nginx access logs record the request line and headers only — never the POST body. The injection payload never appears in Splunk. Detection is limited to behavioral signals (unusual IP, status pattern). This is a real architectural limitation documented in [IR-MER-2026-001](../incident-reports/IR-MER-2026-001-external-webapp-attack.md). Closing this gap requires a WAF with request body inspection or application-level logging.

---

## Attack 2 — Credential Stuffing
**OWASP A07 · MITRE T1110.004**

Eight common passwords tested against the admin account using a curl loop with correct JSON formatting. The endpoint had no rate limiting and no account lockout. `admin123` succeeded on the third attempt.

![bash loop output — admin123 cracked on attempt 3, full admin JWT returned](../screenshots/phase4/phase4-05-bruteforce-attack-success.png)

**Detection query:**
```spl
index=webapp uri="*login*" method=POST
| bucket _time span=1m
| stats count by clientip, _time
| where count > 5
```

Groups login POSTs into 1-minute buckets and flags any source IP exceeding 5 attempts per minute — a threshold grounded in the Phase 3 baseline where the entire pre-attack login history was 3 failed attempts total.

![Volume spike from 10.0.0.100 confirmed — hundreds of attempts visible in Splunk](../screenshots/phase4/phase4-06-bruteforce-detected-splunk.png)

**Alert threshold query result** — the query the scheduled alert runs on:

![Alert threshold query showing Kali's attack window with attempt counts](../screenshots/phase4/phase4-07-bruteforce-alert-threshold.png)

**Finding:** Unlike SQLi, this attack is fully visible from access logs — the signal is volume and timing, not payload content. The contrast with Phase 3 baseline (3 failed logins vs. 1,400+) makes the detection unambiguous.

---

## Attack 3 — DOM-Based XSS
**OWASP A03 · MITRE T1190**

The Juice Shop search parameter is reflected into the Angular DOM without sanitization. Navigating to `/#/search?q=<iframe src="javascript:alert('xss')">` executes arbitrary JavaScript in the browser — a delivery mechanism for session hijacking, credential theft, or malicious redirects.

![JavaScript alert confirms arbitrary code execution in the victim's browser](../screenshots/phase4/phase4-09-xss-browser-execution.png)

Juice Shop's internal challenge tracker independently confirms the attack succeeded:

![Juice Shop challenge system confirms DOM XSS challenge solved](../screenshots/phase4/phase4-09b-juiceshop-challenges-solved.png)

**Detection query** (catches the same payload sent directly via curl to the API):
```spl
index=webapp
| where match(uri, "(?i)(iframe|script|javascript:|onerror)") AND NOT match(uri, "\.js$")
| table _time, clientip, uri, status, useragent
```

![API-layer XSS attempt caught — curl user agent and injection syntax both visible](../screenshots/phase4/phase4-10-xss-detected-splunk.png)

**Finding:** The browser-based DOM XSS is completely undetectable from server logs. URL fragments (`#/search?q=...`) are stripped by the browser before making the HTTP request — the server never receives the payload. The detection above only catches the curl-based API variant. Closing this gap requires Content Security Policy headers. This is a genuine blind spot relevant to any application using client-side routing.

---

## Attack 4 — IDOR (Broken Access Control)
**OWASP A01 · MITRE T1190**

The application checks authentication (valid JWT required) but not authorization (does this basket belong to the requesting user?). Using a valid token for account `analyst@meridian-test.local` (basket ID 6), baskets 1, 2, and 3 belonging to other users are accessed by sequentially incrementing the ID in the API path.

![Three other users' full basket contents returned — authentication present, authorization absent](../screenshots/phase4/phase4-12-idor-cross-basket-access.png)

**Detection query:**
```spl
index=webapp uri="*/rest/basket/*"
| rex field=uri "basket/(?<basket_id>\d+)"
| stats values(basket_id) as accessed_baskets, dc(basket_id) as unique_baskets by clientip
| where unique_baskets > 1
```

Extracts basket IDs from each URI and flags any source IP accessing more than one distinct basket. A legitimate user has exactly one basket.

![IDOR detected — 10.0.0.100 accessed basket IDs 1, 2, and 3 in a single session](../screenshots/phase4/phase4-13-idor-detected-splunk.png)

**Finding:** Clean detection from URI patterns alone — no payload inspection needed. Sequential ID enumeration across a user-scoped resource produces a distinctive behavioral signature that cannot be produced by legitimate usage.

---

## Attack 5 — Path Traversal
**OWASP A05 · MITRE T1190**

Directory traversal attempts to read files outside the web root by encoding `../` sequences in the URL. Two encoding variants tested to assess defense depth.

Standard encoding (`..%2f`) — blocked by Nginx at the proxy layer before reaching the application. Double encoding (`..%252f`) — bypasses Nginx normalization, reaches Juice Shop, and is blocked by the application's own file extension whitelist (only `.md` and `.pdf` files permitted). The 403 response also leaked internal file paths in the stack trace — minor information disclosure that would assist an attacker in mapping the application.

![Double-encoded traversal bypasses Nginx, blocked by application whitelist — stack trace leaks internal paths](../screenshots/phase4/phase4-14-path-traversal-attack.png)

**Detection query:**
```spl
index=webapp
| where match(uri, "(?i)(%2e%2e%2f|\.\.%2f|\.\./|%252e%252e|%252f)")
| table _time, clientip, uri, status
```

![Both encoding variants detected via URI pattern matching](../screenshots/phase4/phase4-15-traversal-detected-splunk.png)

**Finding:** Two-layer defense confirmed effective. The detection catches both encoding variants, which is important — a detection that only matches `%2e%2e%2f` would miss the double-encoded bypass that actually reached the application.

---

## Attack 6 — Price Tampering (Business Logic Abuse)
**OWASP A04 · MITRE T1565.001**

Attempting to inject a client-supplied `price` field into the basket item update API to purchase items below their listed price.

```bash
curl -X PUT "http://10.0.0.33:8080/api/BasketItems/12" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"quantity": 1, "price": 0.01}'
```

The response returns `status: success` but the price field is absent from the returned object. Juice Shop calculates price server-side from the product catalog at checkout — the client-supplied price value is silently ignored.

![Request accepted, price field silently ignored — server-side calculation prevents exploit](../screenshots/phase4/phase4-17b-price-field-injection.png)

**Finding:** Not exploitable. This is a positive finding — the application's design correctly prevents client-side price manipulation. Documenting a successfully defended surface demonstrates thorough testing, not just searching for exploitable vulnerabilities.

---

← [Phase 2+3](phase2-3-spl-log-anatomy.md) · [Back to README](../README.md) · [Phase 5 →](phase5-insider-threat.md)
