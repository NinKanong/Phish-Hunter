# DOMINUS ULTIMATE V29 — Silent AI + Global Live Map + OSINT + Report Center

## Purpose

V29 separates the URL/Domain analyst from the global visualization surface while making the investigation UI drill-down capable.

## 1. Drill-down investigation

Domain Health / Recon cards are real buttons. A click opens an evidence modal and automatically attempts to load the complete normalized module through the isolated investigation API. The modal exposes the original check, provenance, confidence, recommendation, pivots, and returned module payload.

The same isolation interaction is available on evidence/timeline/hosting/service/OSINT field rows where structured payloads exist.

## 2. Global Live Map

The Live Global Map is now a map-only workspace. Domain Health / Recon, Live Signals, case isolation controls, and investigation logs are not embedded in this view.

The map provides:

- 3D orthographic globe
- 2D world projection
- target public-IP infrastructure trace
- provider-backed approximate network geolocation
- target focus and auto-location
- target relationship arcs when multiple locations are returned
- live earthquake layer via USGS public feed
- live aircraft layer via OpenSky public feed
- global search across target objects and live objects
- fullscreen, fit, reset, wheel zoom and drag rotation
- UTC clock and feed status
- clickable live-object dossier
- explicit unavailable/degraded provider states

Target IP seeds can be supplied from the completed scan so geolocation can start from already-observed public addresses instead of waiting for another DNS resolution pass.

The system must never turn a country string into an exact coordinate and must not infer employee/home locations.

## 3. Advanced OSINT direct launch

Each OSINT category has target-prepared outbound sources. The category click opens the primary source immediately and also exposes the complete source drawer for alternate providers.

Each source record carries:

- source name
- URL
- category
- access mode
- whether the URL supports automatic target searching
- a note explaining the source behavior

Access modes include public-web, archive, login-dependent and api-dependent.

## 4. Silent AI

The standalone AI Investigation page is removed.

AI/analyst assistance is embedded in the investigation record and UI as an evidence-grounded silent analyst state. It is designed to summarize evidence, surface anomalies, prioritize pivots and support analyst reasoning without presenting unsupported attribution or invented provider results.

Optional external model providers remain a deployment configuration concern; the local evidence layer remains deterministic and provider-scoped.

## 5. Report Center

A dedicated Report Center is included with:

### Analyst documents

- PDF
- DOCX
- Excel XLSX
- PowerPoint PPTX
- interactive HTML
- print HTML
- Markdown
- JSON
- complete ZIP bundle

### Machine-readable / detection / graph outputs

- STIX
- MISP Event
- SARIF
- GraphML
- GEXF
- DOT
- Mermaid
- MITRE Navigator
- YARA
- Sigma
- Suricata
- Snort
- Zeek
- CSV
- TSV
- IOC CSV
- Connections CSV
- XML
- YAML

The XLSX export is multi-sheet and includes summary, health/recon, findings, assets, evidence, timeline and OSINT data.

## 6. Safety and evidence policy

V29 remains passive-first and evidence-first.

- Provider-dependent data is not fabricated.
- Public IP geolocation is approximate network/provider geography.
- Active DNS/service/internal enumeration requires explicit authorized scope.
- AD data is only expected through an authorized internal connector/export.
- Breach/exposure content is treated as privacy-sensitive intelligence and is not a credential repository.
- Relationship confidence and risk are separate dimensions.

## 7. Verification performed

Verified in the build workspace:

- focused V29 regression tests: 13 passed
- full suite: 100% test cases reached completion in the run, but the pytest process did not exit before the execution timeout
- Python bytecode compilation: passed for touched modules
- rendered result: HTTP 200
- browser JavaScript extracted from rendered result: Node syntax check passed
- report formats: PDF, DOCX, XLSX, PPTX, HTML, JSON, ZIP and machine-readable exports returned HTTP 200
- XLSX: 7 worksheets and ZIP integrity passed
- bundle ZIP: 53 files and ZIP integrity passed
- live-map public IP seed: public IP was accepted while provider geolocation/feed failures were reported as unavailable
- private loopback target: explicitly blocked from plotting

## 8. Deployment note

The development sandbox cannot reach several external providers because outbound DNS/network access is restricted. The final product therefore preserves explicit provider-unavailable states rather than substituting synthetic live intelligence.
