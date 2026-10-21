# DOMINUS ULTIMATE V27 — Live Earth Target Observatory

V27 upgrades the URL & Domain Analyst map from a basic infrastructure globe into a target-focused Earth observatory inspired by the interaction patterns of modern live-world visualization products.

## Live Earth surface

- 3D orthographic globe with bundled world geometry
- 2D world view
- drag rotation
- wheel zoom
- Fit / Reset
- fullscreen Earth mode
- layer toggles
- Earth search/filter for observed signals
- click / double-click evidence selection
- right-click location dossier
- target-focused World Pulse panel
- Live Signals panel
- Live Log
- geographic evidence arcs
- country-level observation anchors
- exact provider coordinates when available
- corporate/provider branch locations when explicitly returned
- cross-case geographic isolation

## Target-domain layers

- Target domain
- IP / network observations
- observed countries
- company / branches
- DNS relationships
- certificate names
- ASN / hosting

No private employee/home locations are inferred. Country centroids are explicitly visualization anchors, not exact host locations.

## Domain reconnaissance health matrix

V27 includes 28 evidence checks covering:

- DNS Records
- DNS Health
- IP & ISP
- Reverse DNS
- CDN Bypass
- MX Analysis
- SPF Chain
- Mail Security
- RDAP / WHOIS
- BGP / ASN
- SSL / crt.sh
- Reverse IP
- DNSSEC Chain
- HTTP / HTTPS
- Web Policy
- TLS Posture
- CAA
- DMARC
- DKIM
- Passive DNS
- Certificate Reuse
- Technology Stack
- Corporate Branches
- GeoIP
- Hosting / Cloud
- Services / Banners
- Threat Reputation
- Breach Exposure

Each check is evidence-state aware: `OK`, `HIT`, `WARN`, or `—` when the required observation/provider is unavailable.

## Verification

- Python compileall: passed
- full pytest suite: passed
- 14 additional Earth observatory tests included in the full suite
- local Uvicorn server: passed
- URL/domain workspace: HTTP 200
- bundled world geometry: HTTP 200
- real local URL/domain scan: HTTP 202 → result HTTP 200
- generated result contains 28 Earth checks
- generated result contains Live Earth search, layers, fullscreen and Live Log controls
- generated browser script: `node --check` passed
- ZIP integrity: passed

External providers remain source-dependent. The local environment used for verification cannot be treated as proof of live RDAP/IP geolocation availability; V27 therefore reports unavailable provider observations instead of fabricating them.
