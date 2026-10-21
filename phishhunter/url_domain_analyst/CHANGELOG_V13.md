# URL & Domain Analyst V13 — DNSDumpster-style Attack Surface Upgrade

## What changed
- Added a dedicated DNSDumpster provider adapter under `connectors/providers/dnsdumpster.py`.
- Added normalized A/AAAA attack-surface inventory with Host, IP, ASN, ASN Name, ASN range, PTR, country, open services, banner details, and dataset-scoped RevIP neighbors.
- Added detailed service/banner flattening for HTTP/HTTPS protocol observations, including application, product, version, server, title, CN and alternative names.
- Added server-side attack-surface API filtering/pagination by country, ASN and service.
- Added service/banner CSV export.
- Added an isolated-result fallback that derives the attack-surface view directly from DNSDumpster evidence when a partial vNext payload is missing.
- Improved domain registered-domain handling to use an installed Public Suffix List library when available, with the existing safe curated fallback otherwise.
- Improved the evidence-backed world map interaction: click provider-returned points or the map background to inspect the nearest returned infrastructure observation.
- Added regression coverage for sparse results and DNSDumpster-shaped payloads.

## Evidence policy
- No port scanning is performed by this module.
- RevIP is labelled `dataset-correlation` unless a separate reverse-IP provider supplies a result.
- Country and location are reported only from provider-returned data or explicitly labelled country-level visualization.
- Internal SIEM/EDR/firewall/ERP/security-stack products are never inferred as fact without supporting public or authorized provider evidence.
