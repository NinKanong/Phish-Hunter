# URL & Domain Analyst V17

This release keeps the URL/domain analyst isolated and deepens the attack-surface model around DNSDumpster-style host/IP/ASN/banner datasets. DNSDumpster currently documents domain API responses containing DNS records, ASN owner/netblocks and banner records, with API authentication using `X-API-Key`; free accounts are limited to 50 records and the API enforces one domain request per two seconds.

## Data model
- A/AAAA host inventory
- IP / ASN / ASN name / netblock
- banner/service observations
- dataset-scoped reverse-IP neighbors
- country and location evidence
- service/product matrix
- hosting/network matrix
- OSINT pivot matrix
- field coverage inventory

## Boundaries
No private-network discovery, fake dark-web crawling, fabricated employees, or unsupported attribution is emitted. Third-party/private signals are provider dependent.
