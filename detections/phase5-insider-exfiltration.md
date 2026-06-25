# Detection: Insider Threat — Data Exfiltration Chain

**MITRE ATT&CK:**
- T1005 Data from Local System (Stage 1 — File Access)
- T1560.001 Archive Collected Data (Stage 2 — Compression)
- T1048 Exfiltration Over Alternative Protocol (Stage 3 — Network Transfer)

**Severity:** Critical

## Individual Detection Queries

### Stage 1 — File Access
```spl
index=windows EventCode=4663 Object_Name="*CustomerExports*"
| table _time, Account_Name, ObjectName, AccessMask
```

### Stage 2 — Compression (PowerShell Module Logging)
```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| where match(_raw, "(?i)Compress-Archive")
| table _time, ComputerName, _raw
```

### Stage 3 — Exfiltration (Network Connection)
```spl
index=windows EventCode=5156 Destination_Port=4444
| table _time, Application_Name, Source_Address, Destination_Address, Destination_Port
```

## Correlated Detection (Centerpiece Query)
```spl
index=windows (EventCode=4663 Object_Name="*CustomerExports*") OR (EventCode=4103 _raw="*CompressFilesHelper*") OR (EventCode=5156 Destination_Port=4444)
| transaction host maxspan=30m
| where eventcount >= 3
| table _time, host, eventcount, duration
```

## Alert
Saved as: Meridian - Insider Threat Data Exfiltration Chain
Schedule: Every 10 minutes (cron: */10 * * * *)
Severity: Critical

## Key Technical Finding
Native PowerShell cmdlets (Compress-Archive) do NOT trigger Event ID 4688 (Process Creation).
Detection required enabling PowerShell Module Logging (Event ID 4103) via registry policy.
Network exfiltration detection required enabling Filtering Platform Connection auditing (Event ID 5156).
Neither is enabled by default on Windows 11.
