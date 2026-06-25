# Phase 6 — Detection Engineering & Alerts

## Overview
The best SPL queries are worthless if nobody sees them fire. All three core detections from Phase 4 and Phase 5 are converted into scheduled Splunk alerts that run automatically, add to the triggered alerts queue, and are visible on the SOC dashboard.

---

## Alert 1 — Brute Force Login Detected

**Severity:** High
**Schedule:** Every 5 minutes (`*/5 * * * *`)
**Trigger:** Number of results > 0

```spl
index=webapp uri="*login*" method=POST
| bucket _time span=1m
| stats count by clientip, _time
| where count > 5
```

**Tuning note:** During testing, a 1,440-event anomaly appeared from background socket.io polling misclassified as login traffic. In production, known service accounts and health-check IPs should be excluded from this query.

![Brute force alert saved](../screenshots/phase6/phase6-01-bruteforce-alert-saved.png)

---

## Alert 2 — Insider Threat Data Exfiltration Chain

**Severity:** Critical
**Schedule:** Every 10 minutes (`*/10 * * * *`)
**Trigger:** Number of results > 0

```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*")
    OR (EventCode=4103 _raw="*CompressFilesHelper*")
    OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
```

This is the highest-value alert in the lab. It only fires when all three stages of the insider kill chain occur on the same host within 30 minutes — virtually no false positive risk.

![Insider threat alert](../screenshots/phase6/phase6-02-insider-alert.png)

---

## Alert 3 — Web Application Injection Attempt

**Severity:** High
**Schedule:** Every 5 minutes (`*/5 * * * *`)
**Trigger:** Number of results > 0

```spl
index=webapp
| where match(uri, "(?i)(or\s+1=1|--|iframe|script|javascript:)") AND NOT match(uri, "\.js$")
| table _time, clientip, uri, status, useragent
```

**Tuning note:** The `.js$` exclusion prevents static JavaScript files from triggering false positives. User agent anomalies (curl, sqlmap) alongside injection patterns should be treated as higher confidence.

![Injection alert](../screenshots/phase6/phase6-03-injection-alert.png)

---

## All Three Alerts Active

All alerts visible firing on the Meridian SOC Dashboard (Panel 6 — Meridian Alert Activity) showing `status: success` on scheduled runs every 5-10 minutes.

---

← [Phase 5](phase5-insider-threat.md) | [Back to README](../README.md) | [Phase 7 →](phase7-dashboard-incidents.md)
