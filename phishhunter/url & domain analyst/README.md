# Phish-Hunter URL & Domain Analyst — V20

This is the requested isolated source area for the URL & Domain Analyst.

## Runtime rule

Python's canonical executable package is:

`phishhunter/url_domain_analyst/`

The human-facing mirror uses spaces and `&` exactly as requested:

`phishhunter/url & domain analyst/`

The mirror contains architecture, contracts, provider maps, and release manifests. Executable modules stay in the canonical package so imports remain deterministic.

## V20 workflow

1. Minimal DNSDumpster-style intake: one URL/domain field and **Start Test!**.
2. Asynchronous job is created immediately.
3. Browser receives real Server-Sent Events instead of a fake timer.
4. Base engine performs bounded passive-first collection.
5. Deep pipeline emits module-level progress for URL anatomy, domain anatomy, DNS, RDAP, CT, HTTP, TLS, infrastructure, reputation, breach/provider state, detections, graph, risk, evidence, geography, services, attack surface, OSINT, cloud/ASN, reasoning and case planning.
6. Result opens only after the actual investigation is complete.
7. Provider-dependent capabilities remain explicitly unavailable when credentials/data sources are not configured.

## Safety boundary

The system is passive-first and provider-backed. It does not execute arbitrary shell commands, dynamically execute target JavaScript, crawl dark-web markets, scrape LinkedIn, or fabricate missing intelligence.

## V21 Ultra Deep

V21 adds:
- interactive worldwide country highlight layers for System Locations;
- bounded public-IP geolocation enrichment with provider provenance;
- defensive C2/malware-infrastructure triage;
- infrastructure clustering across provider-returned IP/ASN observations;
- analyst coverage matrix and expanded Command Center;
- 21 result modules while retaining the evidence-first/provider-scoped model.

C2 analysis is strictly defensive: it identifies provider-returned and heuristic indicators but does not connect to, control, beacon to, exploit, or execute commands against C2 infrastructure.

## V25 DOMINUS ULTIMATE

V25 adds the 15-category Advanced OSINT command center, 545 evidence-field contracts, 360 source/provider/adapter contracts, 45 priority pivot actions, and a real-world local globe renderer based on the bundled world geometry. Geographic evidence remains provider-backed; missing provider observations are never fabricated.
