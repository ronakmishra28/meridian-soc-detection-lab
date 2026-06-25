# Detection: Path Traversal

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
**OWASP:** A05:2021 Security Misconfiguration
**Severity:** Medium

## SPL Query
```spl
index=webapp
| where match(uri, "(?i)(%2e%2e%2f|\.\.%2f|\.\./|%252e%252e|%252f)")
| table _time, clientip, uri, status
```

## Detection Logic
Pattern matches both single and double-encoded directory traversal sequences.

## Finding
Nginx blocked single-encoded traversal (400 Bad Request) at the proxy layer.
Double-encoding (%252f) bypassed Nginx normalization but was blocked by Juice Shop's
own file extension whitelist (.md/.pdf only). Two-layer defense confirmed working.

## False Positive Considerations
Extremely low false positive rate — legitimate requests do not contain encoded ../sequences.
