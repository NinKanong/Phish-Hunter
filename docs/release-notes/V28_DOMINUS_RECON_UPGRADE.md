# DOMINUS ULTIMATE V28 — Recon + Domain Health + Registrant + Earth Upgrade

## What changed

V28 adds a dedicated evidence-first **Domain Health / Recon** layer, a named open-source recon tool contract catalog, and a separated **GLOBAL LIVE MAP** workspace. The global map is intentionally independent from Domain Health / Recon and contains only map controls, live-feed layers, and optional provider-backed case overlays.

### 1. Domain Health / Recon

The dashboard now has a first-class 28-check matrix:

1. DNS Records
2. DNS Health
3. IP & ISP
4. Reverse DNS
5. CDN Bypass
6. MX Analysis
7. SPF Chain
8. Mail Security
9. RDAP / WHOIS
10. BGP / ASN
11. SSL / crt.sh
12. Reverse IP
13. DNSSEC Chain
14. HTTP / HTTPS
15. Web Policy
16. TLS Posture
17. CAA
18. DMARC
19. DKIM
20. Passive DNS
21. Certificate Reuse
22. Technology Stack
23. Corporate Branches
24. GeoIP
25. Hosting / Cloud
26. Services / Banners
27. Threat Reputation
28. Breach Exposure

Every check carries state, detail, prerequisites, source, confidence, findings and next-action guidance. Missing providers remain `—` / unavailable instead of being converted into a positive result.

### 2. Deep Registrant Analyst

Registrant analysis now has a 62-field contract covering:

- identity and registry contact fields
- privacy/redaction state
- historical identity placeholders
- corporate correlation fields
- reverse-WHOIS placeholders
- related domains, IPs, ASNs and certificates
- graph relationships already observed in the case
- evidence/source state
- confidence and analyst pivots

The system does **not** infer private-person identity from a name, address, email or similarity. Registry redaction is preserved as a privacy state rather than treated as suspicious.

### 3. Seven-stage Recon Architecture

The case now exposes a structured plan:

- M1 Passive OSINT Gathering
- M2 Permutation & Family Engine
- M3 Active DNS Enumeration (gated)
- M4 Authorized Internal / AD Enumeration (gated)
- M5 Resolution & Validation (gated)
- M6 Service / Web Fingerprinting (gated)
- M7 Graph / Correlation / Reporting

Active and internal modules are represented as integration contracts and are disabled unless explicit scope is present. A public web scan never silently turns into arbitrary port scanning, brute forcing, AD enumeration or exploitation.

### 4. Named Open-Source Tool Fabric

V28 includes **149 named tool/integration contracts**, including:

- Amass, Subfinder, Assetfinder, Findomain
- MassDNS, PureDNS, ShuffleDNS, DNSx, DNSRecon
- dnsgen, AlterX, Gotator, dnstwist
- httpx, Katana, Hakrawler, Gospider, ffuf, Feroxbuster, Gobuster
- Wappalyzer, WhatWeb, testssl.sh, sslyze, OpenSSL
- Nmap, Naabu, Masscan, RustScan, ZMap
- Neo4j, Cytoscape.js, D3.js, Cartography
- MISP, OpenCTI, OpenSearch, Wazuh, Zeek, Suricata
- BloodHound CE, SharpHound, ldapsearch, Impacket, NetExec
- SpiderFoot, Recon-ng, theHarvester, Sherlock, Maigret, GHunt
- Nuclei, NVD, CISA KEV, OSV.dev, Trivy, Grype, Syft
- SQLite, PostgreSQL, DuckDB, jq, yq, OpenTelemetry, Prometheus, Grafana

A catalog entry means a named adapter/integration contract. It does not claim the binary is installed or that a paid API account is active.

### 5. Global Live Map

The Live Global Map was redesigned as a dedicated map-only workspace. The previous `LIVE SIGNALS`, `Target domain`, `ISOLATE ACROSS CASE`, and embedded `DOMAIN HEALTH / RECON` panels were removed from the map. Domain Health / Recon remains a separate analyst module.

The map now provides:

- 3D globe and 2D world modes
- drag rotation and wheel zoom
- global search across loaded live objects
- fullscreen mode
- floating layer menu
- USGS earthquake live-feed adapter
- OpenSky aircraft live-feed adapter
- UTC live clock and feed freshness indicators
- latitude/longitude cursor readout
- local bundled world geometry with no required map-tile CDN
- explicit degraded state when a live provider cannot be reached
- no domain-specific health, dossier, isolation or case panels inside the map

The frontend never fabricates live objects. A feed is marked unavailable when its provider does not return data.
