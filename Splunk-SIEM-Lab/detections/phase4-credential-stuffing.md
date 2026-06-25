# Detection: Credential Stuffing / Brute Force

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)
**OWASP:** A07:2021 Identification and Authentication Failures
**Severity:** High

## SPL Query
```spl
index=webapp uri="*login*" method=POST
| bucket _time span=1m
| stats count by clientip, _time
| where count > 5
```

## Detection Logic
More than 5 login attempts from a single IP within a 1-minute window.
Threshold chosen to avoid false positives from legitimate users mistyping passwords.

## Alert
Saved as: Meridian - Brute Force Login Detected
Schedule: Every 5 minutes (cron: */5 * * * *)
Severity: High
