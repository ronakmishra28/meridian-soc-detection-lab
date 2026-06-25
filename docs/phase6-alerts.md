# Phase 6 — Detection Engineering & Alerts

The three core detections are converted into scheduled Splunk alerts. Each includes a tuning note — production-ready detection engineering means understanding what generates false positives, not just what generates true positives.

---

## Alert 1 — Brute Force Login Detected

Fires when a single source IP exceeds 5 POST requests to the login endpoint within any 1-minute window. The threshold is anchored to the Phase 3 baseline: the entire pre-attack login history was 3 failed attempts — any rate above 5/minute is operationally anomalous.

**Severity:** High · **Schedule:** `*/5 * * * *` (every 5 minutes)

```spl
index=webapp uri="*login*" method=POST
| bucket _time span=1m
| stats count by clientip, _time
| where count > 5
```

![Brute force alert configured and saved in Splunk](../screenshots/phase6/phase6-01-bruteforce-alert-saved.png)

**Tuning note:** Testing surfaced a 1,440-event-per-minute anomaly from background socket.io polling traffic misclassified as login requests. In production, health-check IPs and service accounts should be excluded with `NOT clientip IN (...)`.

---

## Alert 2 — Insider Threat Data Exfiltration Chain

Fires only when all three kill chain stages occur on the same host within 30 minutes. The `transaction` correlation and `eventcount >= 3` threshold mean this alert has near-zero false positive risk — legitimate activity rarely combines sensitive file access, compression, and an outbound curl to a non-standard port in a single 30-minute window.

**Severity:** Critical · **Schedule:** `*/10 * * * *` (every 10 minutes)

```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*")
    OR (EventCode=4103 _raw="*CompressFilesHelper*")
    OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
```

![Insider threat alert configured and saved in Splunk](../screenshots/phase6/phase6-02-insider-alert.png)

**Tuning note:** If a scheduled backup process accesses `CustomerExports`, it may trigger Stage 1 (4663). Exclude the backup service account from the 4663 filter, or require that Stage 3 (5156 on port 4444) must also be present — a backup process wouldn't satisfy that condition.

---

## Alert 3 — Web Application Injection Attempt

Flags URIs containing injection syntax patterns. The `NOT match(uri, "\.js$")` exclusion prevents static JavaScript files with common naming patterns from generating false positives on every page load.

**Severity:** High · **Schedule:** `*/5 * * * *` (every 5 minutes)

```spl
index=webapp
| where match(uri, "(?i)(or\s+1=1|--|iframe|script|javascript:)") AND NOT match(uri, "\.js$")
| table _time, clientip, uri, status, useragent
```

![Injection alert configured and saved in Splunk](../screenshots/phase6/phase6-03-injection-alert.png)

**Tuning note:** Non-browser user agents (`curl`, `sqlmap`) alongside injection syntax should be treated as high-confidence positives. A real browser sending a request that incidentally contains `--` in a product search string is a candidate for contextual exclusion based on the full URI pattern.

---

← [Phase 5](phase5-insider-threat.md) · [Back to README](../README.md) · [Phase 7 →](phase7-dashboard-incidents.md)
