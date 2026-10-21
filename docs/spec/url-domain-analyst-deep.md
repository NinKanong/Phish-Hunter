# URL & Domain Analyst — Unified Deep Investigation Contract v2

The URL Analyst and Domain Analyst are one investigation surface. The analyst starts with a target/intake step, then produces a left-side evidence rail plus a source-backed dossier, relationship graph and machine-readable case package.

## 1. Investigation lifecycle
1. Evidence Intake: target URL/domain or indicator intake file.
2. Normalization: canonical URL, IDNA/ASCII hostname, FQDN, registered domain, target type.
3. Passive collection: RDAP, DNS, CT, current HTTP/TLS and fixed provider adapters.
4. Correlation: domain, registrar, IP, PTR, NS, MX, certificates, subdomains, technologies and provider signals.
5. Triage: explainable risk score, confidence and signal provenance.
6. Investigation: evidence isolates, pivot explorer, relationship graph, timeline, IOC explorer and provider matrix.
7. Response: analyst task plan, ATT&CK observations, evidence digest and export-ready JSON.

## 2. URL forensics
- raw URL and normalized URL
- scheme / hostname / registered domain / port
- standard vs non-standard port
- path, path depth and query presence
- query parameter count and parameter names
- redirect-style parameters such as `next`, `url`, `redirect`, `return`, `dest`
- percent-encoding count
- double-encoding indicators
- fragment presence
- userinfo presence in URL
- hostname label count
- URL length
- URL-vs-domain classification

These are triage signals. They do not prove maliciousness.

## 3. Domain identity
- FQDN
- registered domain
- label count / subdomain depth
- length / entropy
- IDNA / punycode
- mixed-script detection
- Unicode homoglyph indicators
- heuristic lookalike candidates
- candidate edit distance / substitution / deletion / transposition / prefix/suffix variants

## 4. WHOIS / RDAP lifecycle
- RDAP source and URL
- object class / handle
- registrar entity
- public entity roles
- public organization / name / email / phone / address when returned
- registration / update / expiration events when published
- domain age
- domain status codes
- nameservers
- secure DNS flags
- notices / remarks
- raw RDAP evidence

Historical WHOIS is provider-dependent; a single current RDAP response is never represented as full ownership history.

## 5. DNS intelligence
- A / AAAA
- CNAME
- MX
- NS
- TXT
- SOA
- CAA
- SRV
- NAPTR
- DNSKEY
- DS
- RRSIG
- TLSA
- SSHFP
- current PTR for current discovered IP addresses
- per-record TTL
- resolver/source
- total record count
- TTL min/max
- NS/MX counts
- DNSSEC chain observation

## 6. Email authentication posture
- SPF TXT observation
- `_dmarc.<domain>` TXT observation
- `_mta-sts.<domain>` TXT observation
- `_smtp._tls.<domain>` TXT observation
- `default._domainkey.<domain>` DKIM spot check
- explicit distinction between observed record, no record and provider/error state
- DKIM selector limitation: the default selector is not a complete selector inventory

## 7. Infrastructure relationship intelligence
Current evidence can correlate:

`Domain → Registered Domain → Registrar`

`Domain → A/AAAA → IP → PTR`

`Domain → NS`

`Domain → MX`

`Domain → Certificate → SAN/Subdomain`

`Domain → HTTP → Technology`

`Domain → Reputation Signal`

`Breach Identity → Domain`

Every relationship should have a source reference and confidence value.

## 8. Certificate Transparency and TLS
- certificate record ID
- issuer CA
- common name
- observed SAN/name values
- serial number
- not-before / not-after
- CT certificate count
- discovered hostname count
- current live TLS version
- cipher
- issuer
- live SAN count
- wildcard SAN indicator
- certificate SHA-256 fingerprint
- live certificate expiry days

CT entries are passive historical observations and are not proof that a hostname is active now.

## 9. Web and landing-page observation
- public HTTP status
- final URL
- redirect count and redirect chain
- response size
- response content type
- page title
- Server / X-Powered-By headers
- cache control
- CSP
- forms
- password input indicators
- form actions
- cross-origin form actions
- observed links
- observed scripts
- security headers
- safe technology fingerprints

The web probe does not execute page JavaScript, detonate downloaded payloads, run arbitrary shell commands or scan arbitrary ports.

## 10. Security posture
Track presence/value for:
- HSTS
- CSP
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- COOP
- CORP
- CORS exposure signals
- cookie Secure / HttpOnly / SameSite observations

## 11. Reputation and threat intelligence
Fixed provider adapters can include:
- VirusTotal
- urlscan.io
- Google Safe Browsing
- AbuseIPDB
- PhishTank / OpenPhish
- URLhaus / ThreatFox
- AlienVault OTX
- MISP / OpenCTI
- Censys / Shodan / GreyNoise / FOFA / ZoomEye / Netlas
- Spamhaus / Talos / other configured intelligence providers

For each connector store:
- provider
- status
- timestamp
- query indicator
- returned signal
- raw/provider response boundary
- confidence

No-hit is not equivalent to clean.

## 12. Breach / leak intelligence
The UI exposes an explicit provider matrix for:
- Have I Been Pwned
- IntelX
- DeHashed
- Hudson Rock
- SpyCloud
- Constella
- other authorized enterprise connectors

For HIBP domain search, the domain must be authorized/verified under the provider account. The web service does not fabricate dark-web findings and does not directly crawl Tor or private leak marketplaces.

## 13. Traffic / availability
Observed locally:
- DNS resolves / does not resolve
- HTTP state/status
- TLS state
- HTTP response size
- current reachability

Provider-dependent:
- popularity rank
- estimated traffic volume
- historical prevalence
- historical scans
- passive DNS history

Potential provider paths include urlscan.io, Cloudflare Radar, SimilarWeb and Tranco.

## 14. OSINT Framework-style pivoting
The analyzer keeps a source taxonomy that mirrors OSINT investigation workflows:
- DNS / infrastructure
- certificates / web
- IP / network
- identity / company / OSINT
- threat intelligence
- archives / search
- SOC / IR / forensics
- cloud / infrastructure

Pivots can generate starting queries for:
- search engines
- certificate searches
- historical URL searches
- IP pivots
- identity/organization research

A query is not evidence until the analyst obtains and preserves a source result.

## 15. Tool fabric
The catalog currently contains 285 named integration points. Each is explicitly classified as:
- `live-configured`
- `local-available`
- `local-not-detected`
- `catalog-only`

The catalog covers OSINT Framework, DNS discovery, CT, passive DNS, IP intelligence, reputation, breach intelligence, web archives, threat intel, SOC and forensic ecosystems.

Catalog presence is not represented as live execution.

## 16. Evidence and chain of custody
Every retained evidence record should contain:
- evidence ID
- source/provider
- kind
- observation time
- confidence
- interpretation
- raw observation

The result package contains an application-level SHA-256 digest. This provides integrity checking for exports but is not itself a legal chain-of-custody determination.

## 17. Risk model
The score is a transparent triage aid:
- 0–24: low-risk
- 25–54: suspicious
- 55–79: high-risk
- 80–100: critical

Signals can include:
- mixed script
- homoglyph
- unusual hostname entropy/length
- deep subdomain structure
- redirect chains
- password form
- cross-origin form action
- TLS failure
- provider-confirmed threat signals
- breach exposure

Every signal should include weight, severity, reason and confidence. The score must never be presented as attribution or proof of compromise.

## 18. AI investigation agent
The AI layer receives evidence selected from the investigation result and is instructed to:
- summarize observed facts
- separate fact from hypothesis
- identify missing evidence
- prioritize pivots
- suggest defensive validation steps
- avoid unsupported attribution / ownership / compromise claims

When the OpenAI API is not configured, the rules-and-evidence agent remains available locally.

## 19. Analyst interface requirements
### Initial state
- full-screen command-center shell
- left investigation navigation
- start-inquiry hero card
- Evidence Intake entry point
- target field + upload control
- explicit authorization checkbox
- safe-analysis boundary
- coverage and pipeline status

### Result state
- full-screen left navigation similar to the Network Artifacts workspace
- left evidence rail with target score and quick counts
- entity-isolate tree
- selected-node inspector
- dossier navigation
- graph with interactive node selection and zoom
- DNS tab matrix
- timeline
- evidence search/filter
- IOC explorer
- provider matrix
- breach boundary
- OSINT pivots
- AI task plan
- toolchain filter
- JSON export and digest

## 20. Security boundary
- SSRF guard remains enabled for target fetches.
- Target fetching is bounded.
- JavaScript execution is disabled for the safe page probe.
- No arbitrary shell command execution is added to the web route.
- No direct Tor/dark-web crawler is claimed.
- External-provider result availability is explicit.
- Authorized targets/providers are required for operational enrichment.
