# Detection: SQL Injection — Login Bypass

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
**OWASP:** A03:2021 Injection
**Severity:** Critical

## SPL Query
```spl
index=webapp uri="*login*" method=POST
| stats count, values(status) as statuses by clientip
| where count > 1
```

## Detection Logic
Flags any source IP making multiple POST requests to the login endpoint.
Cannot detect the payload directly — Nginx does not log POST body content.
Behavioral detection only (volume + pattern).

## False Positive Considerations
Password manager auto-fill on page load may trigger 2 requests.
Tune threshold based on baseline observation.

## Tuning
Exclude known internal monitoring/health-check IPs.
