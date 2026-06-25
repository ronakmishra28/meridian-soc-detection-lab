# Detection: IDOR — Basket Enumeration

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
**OWASP:** A01:2021 Broken Access Control
**Severity:** High

## SPL Query
```spl
index=webapp uri="*/rest/basket/*"
| rex field=uri "basket/(?<basket_id>\d+)"
| stats values(basket_id) as accessed_baskets, dc(basket_id) as unique_baskets by clientip
| where unique_baskets > 1
```

## Detection Logic
Flags any single IP accessing more than one distinct basket ID.
A legitimate user only ever needs their own basket — accessing multiple IDs indicates enumeration.

## False Positive Considerations
Admin accounts with legitimate need to view multiple baskets should be excluded by IP/account.
