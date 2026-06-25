# Phase 4 — OWASP Top 10 Attack Detection

## Overview
Six OWASP Top 10 attacks executed from Kali (10.0.0.100) against WEB-PROD-01 (10.0.0.33:8080). For each attack: the technique is explained, the attack is executed, the detection query is written, and genuine findings (including limitations) are documented. Two attacks were successfully blocked — those negative findings are documented with equal rigor.

---

## Attack 1 — SQL Injection (Login Bypass)
**OWASP:** A03 Injection | **MITRE:** T1190

**What it does:** A crafted email field (`' OR 1=1--`) bypasses the login query entirely, returning a valid JWT token for the admin account without knowing the password.

**Attack:**
```bash
curl -X POST http://10.0.0.33:8080/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","password":"x"}'
```

**Result:** Full admin JWT token returned — `"email":"admin@juice-sh.op"`, `"role":"admin"`.

![SQLi admin bypass success](../screenshots/phase4/phase4-02-sqli-admin-bypass-success.png)

**Detection query:**
```spl
index=webapp uri="*login*" method=POST
| stats count, values(status) as statuses by clientip
```

![SQLi detected in Splunk](../screenshots/phase4/phase4-03-sqli-detected-in-splunk.png)

**Key finding:** Nginx access logs do not capture POST body content. The `' OR 1=1--` payload was never logged — only the IP, URI, and status code. Detection is behavioral (volume + pattern) only. Catching the actual payload requires a WAF with body inspection or application-level logging. This is documented in [IR-MER-2026-001](../incident-reports/IR-MER-2026-001-external-webapp-attack.md).

---

## Attack 2 — Credential Stuffing
**OWASP:** A07 Identification and Authentication Failures | **MITRE:** T1110.004

**What it does:** Automated password testing against the login endpoint using a wordlist. No payload injection — just high-volume authentication attempts.

**Attack:** Custom bash loop sending 8 password attempts against `admin@juice-sh.op`. Password `admin123` succeeded on the 3rd attempt.

**Result:** Admin account compromised. No rate limiting or account lockout observed.

![Brute force success](../screenshots/phase4/phase4-05-bruteforce-attack-success.png)

**Detection query:**
```spl
index=webapp uri="*login*" method=POST
| bucket _time span=1m
| stats count by clientip, _time
| where count > 5
```

![Brute force detected](../screenshots/phase4/phase4-06-bruteforce-detected-splunk.png)

**Alert threshold query** — what the scheduled alert runs every 5 minutes:

![Alert threshold](../screenshots/phase4/phase4-07-bruteforce-alert-threshold.png)

**Key finding:** Clean detection — this attack is entirely visible from access logs because the detection signal is *volume and timing*, not payload content. Unlike the SQLi case, no body inspection is needed.

---

## Attack 3 — DOM-Based XSS
**OWASP:** A03 Injection | **MITRE:** T1190

**What it does:** Unsanitized input in the search parameter gets rendered as executable JavaScript in the victim's browser — allows session hijacking, credential theft, or malicious redirects.

**Attack:** `http://10.0.0.33:8080/#/search?q=<iframe src="javascript:alert('xss')">`

**Result:** JavaScript alert executed in browser. Juice Shop's own challenge tracker confirmed "DOM XSS" solved.

![XSS browser execution](../screenshots/phase4/phase4-09-xss-browser-execution.png)

![Juice Shop challenges solved](../screenshots/phase4/phase4-09b-juiceshop-challenges-solved.png)

**Detection query** (API-layer variant):
```spl
index=webapp
| where match(uri, "(?i)(iframe|script|javascript:|onerror)") AND NOT match(uri, "\.js$")
| table _time, clientip, uri, status, useragent
```

![XSS detected in Splunk](../screenshots/phase4/phase4-10-xss-detected-splunk.png)

**Key finding:** The DOM-based XSS via URL fragment (`#/search?q=...`) is completely invisible to server-side logs — browsers strip URL fragments before making HTTP requests. The detection above only catches the same payload sent directly to the API endpoint via curl, not browser-based exploitation. This is a genuine architectural blind spot requiring CSP headers or client-side monitoring to close.

---

## Attack 4 — IDOR (Broken Access Control)
**OWASP:** A01 Broken Access Control | **MITRE:** T1190

**What it does:** The application checks *authentication* (is this a valid user?) but not *authorization* (does this basket belong to this user?). Any authenticated user can access any other user's basket by guessing sequential IDs.

**Attack:** Using a valid JWT token for account `analyst@meridian-test.local` (basket ID 6), access baskets 1, 2, and 3 belonging to other users.

**Result:** All 3 baskets returned successfully — full order contents, product details, and user IDs of other customers exposed.

![IDOR cross-basket access](../screenshots/phase4/phase4-12-idor-cross-basket-access.png)

**Detection query:**
```spl
index=webapp uri="*/rest/basket/*"
| rex field=uri "basket/(?<basket_id>\d+)"
| stats values(basket_id) as accessed_baskets, dc(basket_id) as unique_baskets by clientip
| where unique_baskets > 1
```

![IDOR detected in Splunk](../screenshots/phase4/phase4-13-idor-detected-splunk.png)

**Key finding:** 10.0.0.100 accessed 3 distinct basket IDs — `unique_baskets=3`. This detection works entirely from URI patterns — no body inspection needed. A legitimate user only ever accesses their own basket, so accessing multiple distinct IDs is a reliable signal.

---

## Attack 5 — Path Traversal
**OWASP:** A05 Security Misconfiguration | **MITRE:** T1190

**What it does:** Directory traversal attempts to access files outside the intended web root by encoding `../` sequences in the URL.

**Attack — single encoding (blocked by Nginx):**
```bash
curl -s "http://10.0.0.33:8080/ftp/..%2f..%2f..%2fetc%2fpasswd"
# Result: 400 Bad Request — Nginx rejected at proxy level
```

**Attack — double encoding (bypasses Nginx):**
```bash
curl -s "http://10.0.0.33:8080/ftp/..%252f..%252f..%252fetc%252fpasswd"
# Result: 403 — "Only .md and .pdf files are allowed"
```

![Path traversal attack](../screenshots/phase4/phase4-14-path-traversal-attack.png)

**Detection query:**
```spl
index=webapp
| where match(uri, "(?i)(%2e%2e%2f|\.\.%2f|\.\./|%252e%252e|%252f)")
| table _time, clientip, uri, status
```

![Traversal detected](../screenshots/phase4/phase4-15-traversal-detected-splunk.png)

**Key finding:** Two-layer defense confirmed. Nginx blocked single-encoded traversal at the proxy level. Double-encoding (`%252f`) bypassed Nginx normalization but was blocked by Juice Shop's own file extension whitelist. Stack trace in the error response also leaked internal file paths (`/juice-shop/build/routes/fileServer.js`) — a minor information disclosure worth noting.

---

## Attack 6 — Price Tampering (Business Logic Abuse)
**OWASP:** A04 Insecure Design | **MITRE:** T1565.001

**What it does:** Attempts to inject a client-supplied price into the basket item update request, bypassing server-side price calculation.

**Attack:**
```bash
curl -X PUT "http://10.0.0.33:8080/api/BasketItems/12" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"quantity": 1, "price": 0.01}'
```

**Result:** Request returned `status: success` but the `price` field was silently ignored — not stored, not reflected in the response. Price is calculated server-side from the product catalog at checkout, not stored per basket item.

![Price field injection](../screenshots/phase4/phase4-17b-price-field-injection.png)

**Key finding:** Not exploitable. This is a **positive finding** — the application correctly ignores client-supplied price values. The quantity-cap validation (max 5 per product) also held. Both findings are documented: knowing what's *not* vulnerable is as important as finding what is.

---

← [Phase 2+3](phase2-3-spl-log-anatomy.md) | [Back to README](../README.md) | [Phase 5 →](phase5-insider-threat.md)
