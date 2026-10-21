
## V12.5 hardening / deep OSINT

- Provider payloads are schema-guarded so malformed strings/lists become evidence gaps instead of route-breaking exceptions.
- Global domain parsing uses an optional PSL implementation when the deployment provides one, with deterministic fallback rules.
- Added independent Wappalyzer, official LinkedIn, IPinfo and SecurityTrails provider paths.
- Added public company/workforce profile, search-pivot planner, breach matrix, security-stack observables, CDN/WAF, mail-auth, hosting and temporal heuristics.
- The UI exposes isolated module panes and an evidence-backed world map; locations are provider-returned or explicitly labeled country approximations.
- Workforce export is limited to provider/API-returned observations and never scrapes LinkedIn.
# Phish-Hunter — URL & Domain Analyst vNext

This directory is the rebuild boundary for the URL & Domain Analyst. It is deliberately much larger than the earlier adapter-only module so future work can be done by capability without modifying the rest of Phish-Hunter.

## Architecture

`core/` shared pipeline primitives  
`contracts/` typed evidence/entity/relationship contracts  
`url/` complete URL anatomy and encoding/obfuscation  
`domain/` domain anatomy, PSL/private-suffix boundary and IDN analysis  
`dns/` full DNS record matrix, email auth and DNSSEC posture  
`rdap/` registration lifecycle and entity extraction  
`ct/` certificate transparency aggregation  
`pdns/` passive-DNS integration boundary  
`subdomains/` subdomain discovery/verification boundary  
`infrastructure/` IP/ASN/hosting/CDN/WAF relationships  
`http/` safe HTTP and security-header analysis  
`tls/` TLS/certificate posture  
`content/` HTML/JS/CSS/static-content expansion boundary  
`security/` homograph, typosquat, DGA, tunneling and takeover heuristics  
`reputation/` multi-provider reputation fusion  
`breach/` provider-scoped breach exposure boundary  
`graph/` typed knowledge graph and interaction contract  
`correlation/` entity resolution/campaign clustering boundary  
`scoring/` 10-dimensional explainable risk model  
`ai/` evidence-grounded AI task planning  
`monitoring/` watches, drift and alert triggers  
`evidence/` hashes, provenance and chain-of-custody  
`reporting/` analyst report/export boundary  
`pivots/` pivot suggestions  
`connectors/` named provider adapters + 700 internal capability slots  
`orchestration/` deep pipeline that composes all layers

## 700 capability slots

The supplied blueprint specifies 52 categories totaling 400+ modules. This implementation expands that capability registry to **700 internal capability slots** so the module has room to grow without pretending every external provider is already configured. Third-party providers are tracked separately and only become `live-configured` when credentials/configuration are present.

## Runtime contract

`engine.analyze(target)` first runs the stable Phish-Hunter analyzer and then adds `url_domain_vnext` containing the deeper self-contained analysis. Existing consumers remain compatible because the original result keys are preserved.

## Safety / evidence rules

No result is invented. Provider-dependent intelligence is marked as such. Direct Tor/dark-web crawling is not performed by the web service. Dynamic JavaScript execution and arbitrary shell execution are disabled at this layer.

## Rebuild rule

Start new work in the smallest capability package possible. Use `orchestration/deep_pipeline.py` only to compose capabilities. Do not add another monolithic analyzer.

## Capability scale

52 category packages expose 778 internal capability slots. They are code-owned Phish-Hunter capabilities, not fake claims that 778 external products are already connected. Provider connectors remain status-aware.


## V13 attack-surface layer
The module now includes a DNSDumpster-style evidence surface: A/AAAA host inventory, IP/ASN/network owner, netblock, PTR, provider banners, service/application/version details, country observations, dataset-scoped reverse-IP neighbors, filtered isolated APIs, and CSV exports. See `CHANGELOG_V13.md`.
