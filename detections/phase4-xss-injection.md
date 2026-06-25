# Detection: XSS / Injection Attempt

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
**OWASP:** A03:2021 Injection
**Severity:** High

## SPL Query
```spl
index=webapp
| where match(uri, "(?i)(or\s+1=1|--|iframe|script|javascript:)") AND NOT match(uri, "\.js$")
| table _time, clientip, uri, status, useragent
```

## Detection Logic
Pattern matches injection syntax in URI. Excludes .js files to reduce false positives.
Non-browser user agents (curl, sqlmap) alongside injection patterns indicate tooling.

## Limitation
DOM-based XSS delivered via URL fragment (#) never reaches the server — invisible to this detection.

## Alert
Saved as: Meridian - Web Application Injection Attempt Detected
Schedule: Every 5 minutes (cron: */5 * * * *)
Severity: High
