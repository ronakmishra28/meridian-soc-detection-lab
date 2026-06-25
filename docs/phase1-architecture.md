# Phase 1 — Architecture & Multi-Source Log Ingestion

## Overview
Splunk Enterprise deployed on Mac as the central SIEM. Universal Forwarder installed on 3 endpoints, each shipping logs into separate indexes. OWASP Juice Shop deployed on Ubuntu via Docker, fronted by Nginx to generate realistic web application logs.

---

## Architecture

```
MacBook M4 Pro — Splunk Enterprise 10.2 (indexer + search head)
└── Parallels Desktop
    ├── WEB-PROD-01 · Ubuntu 22.04 (10.0.0.33)
    │     Docker → Juice Shop (port 3000)
    │     Nginx reverse proxy (port 8080) → access_combined logs
    │     Universal Forwarder → webapp + linux indexes
    │
    ├── FIN-WKS-04 · Windows 11 (10.0.0.32)
    │     Security + System + Application + PowerShell Operational logs
    │     Universal Forwarder → windows index
    │
    └── Kali Linux (10.0.0.100)
          Attack machine — no forwarder (attacker machine is never monitored)
```

---

## Splunk Home

![Splunk home](../screenshots/phase1/phase1-01-splunk-home.png)

---

## Juice Shop Running via Nginx

Juice Shop deployed in Docker on port 3000, Nginx reverse proxies on port 8080. All access logs written to `/var/log/nginx/juiceshop-access.log` in `access_combined` format — Splunk auto-extracts `clientip`, `method`, `uri`, `status`, `bytes`, `useragent` from this format with no custom field extraction needed.

![Juice Shop running](../screenshots/phase1/phase1-03-juiceshop-running.png)

---

## All 3 Indexes Active

```spl
index=* | stats count by host, index
```

![All indexes](../screenshots/phase1/phase1-02-all-indexes.png)

---

## Webapp Logs Flowing

![Webapp logs](../screenshots/phase1/phase1-04-webapp-logs.png)

---

## Windows Logs Flowing

![Windows logs](../screenshots/phase1/phase1-05-windows-logs.png)

---

## All 3 Forwarders Active

Monitoring Console → Forwarders: Deployment — confirms all 3 endpoints connected, showing OS, architecture, last connected time, and average KB/s per forwarder.

![Forwarders active](../screenshots/phase1/phase1-07-all-forwarders-active.png)

---

## Key Config Files

- [`configs/webprod01-inputs.conf`](../configs/webprod01-inputs.conf) — Ubuntu UF (syslog, auth.log, Nginx logs)
- [`configs/finwks04-inputs.conf`](../configs/finwks04-inputs.conf) — Windows UF (Security, System, Application, PowerShell/Operational)
- [`configs/outputs.conf`](../configs/outputs.conf) — All forwarders point to `10.0.0.31:9997`
- [`configs/nginx-juiceshop-reverse-proxy.conf`](../configs/nginx-juiceshop-reverse-proxy.conf) — Nginx proxy config

---

← [Back to README](../README.md) | [Phase 2+3 →](phase2-3-spl-log-anatomy.md)
