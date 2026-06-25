# Phase 2+3 — SPL Fundamentals & Log Anatomy

Before running attacks, normal traffic baselines were established using the Nginx access logs already flowing from WEB-PROD-01. This phase serves two purposes: building SPL proficiency on real data before the complexity of attack detection, and creating documented baselines that make anomalies unambiguous in Phase 4.

---

## SPL Structure

Every SPL query follows the same pattern. The part before the first `|` selects and filters raw events. Each `|` pipes those events into the next command, which transforms or aggregates them. Reading SPL means reading left to right — each stage narrows or reshapes the data from the previous one.

```spl
index=webapp uri="*login*" method=POST   ← select events from webapp, filter to login POSTs
| bucket _time span=1m                   ← group by 1-minute time windows
| stats count by clientip, _time         ← count events per IP per window
| where count > 5                        ← keep only windows with >5 attempts
```

---

## HTTP Status Code Distribution — Pre-Attack Baseline

At baseline, nearly all traffic returns `200 OK` — normal browsing, page loads, API calls. This flat distribution is the reference point that makes the 401 spike during credential stuffing immediately recognizable as an attack pattern rather than noise.

```spl
index=webapp | stats count by status
```

![HTTP status code distribution — near-uniform 200 before attacks begin](../screenshots/phase2/phase2-01-status-by-count.png)

---

## HTTP Method Breakdown

GET requests dominate normal traffic (page loads, product browsing, image fetches). POST requests represent user actions — login, basket operations, account creation. An unusual POST rate to a single endpoint against this baseline is a meaningful signal worth investigating.

```spl
index=webapp | stats count by method
```

![GET vs POST method ratio — GET dominant in normal browsing traffic](../screenshots/phase3/phase3-02-method-breakdown.png)

---

## User Agent Baseline — Most Valuable Pre-Attack Observation

At baseline, 100% of traffic originates from a single browser (Chrome on Mac). This uniformity is the most important baseline in the lab. Attack tools — `curl`, `sqlmap`, `Hydra` — either send non-browser user agents or no user agent at all. Their requests stand out completely against this background, making tool-based attacks detectable even without analyzing the payload.

```spl
index=webapp | top useragent
```

![Single browser user agent at baseline — any deviation is anomalous](../screenshots/phase3/phase3-03-useragent-baseline.png)

---

## Login Activity Baseline

Three failed logins (401) and one successful login (200) represent the entire pre-attack login history — all from a single IP (`10.0.0.31`, the analyst's own Mac during normal testing). This is the baseline against which credential stuffing from Kali becomes unambiguous: same endpoint, same status codes, but from a different IP and at a volume of hundreds of attempts per minute.

```spl
index=webapp uri="*login*" method=POST | stats count by status
```

![Login status codes at baseline — 3 failures, 1 success from normal testing](../screenshots/phase2/phase2-03-login-status-breakdown.png)

---

## Failed Logins by Source IP — Foundation of Brute Force Detection

The pre-attack picture: one IP with 3 failed login attempts. After credential stuffing runs in Phase 4, the same query shows `10.0.0.100` (Kali) with over 1,400 attempts. The contrast between these two screenshots is what makes the detection threshold of >5 attempts per minute meaningful — it's not an arbitrary number, it's grounded in what the actual baseline looks like.

```spl
index=webapp uri="*login*" status=401 | stats count by clientip
```

![Failed logins by IP at baseline — single IP, low count, normal activity](../screenshots/phase2/phase2-04-failed-login-by-ip.png)

---

## SPL Commands Used Throughout This Lab

| Command | Purpose in this lab |
|---|---|
| `stats count by X` | Aggregate events — used in every detection query |
| `timechart count by X` | Plot event volume over time — used in dashboard panels |
| `rex field=X "regex"` | Extract a field from raw text — used in IDOR detection to pull basket ID from URI |
| `bucket _time span=Nm` | Group events into time windows — used in brute force rate detection |
| `where match(X, "pattern")` | Filter by regex — used in injection and traversal detection |
| `transaction host maxspan=Nm` | Correlate related events into one incident — centerpiece of insider threat detection |
| `top X` | Most frequent values — used for user agent and URI baselining |

---

← [Phase 1](phase1-architecture.md) · [Back to README](../README.md) · [Phase 4 →](phase4-owasp-detection.md)
