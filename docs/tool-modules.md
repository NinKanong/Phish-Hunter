# Phish-Hunter Tool Module Layout

Each major capability now has a top-level module under `phishhunter/`. This is the rebuild boundary: module-specific engine adapters, schemas, enrichments, graph relationships, reports and AI policy live together so a future tool can be rebuilt without touching unrelated services.

```text
phishhunter/
├── email_analyst/         # Email Analyst
├── url_domain_analyst/    # URL & Domain Analyst
├── file_analyst/          # File Analyst
├── ip_analyst/            # IP Analyst
├── network_artifacts/     # PCAP Analyst (Network)
├── malware_analyst/       # Malware Analyst
├── ransomware_analyst/    # Ransomware Analyst
├── ioc_analyst/           # IOC Analyst
├── phishing_kit_analyst/  # Phishing Kit Analyst
├── threat_intelligence/   # Threat Intelligence
├── sandbox/               # Sandbox
├── reports/               # Reports (Operate)
├── campaigns/             # Campaigns (Operate)
├── threat_actors/         # Threat Actors (Operate)
├── ioc_graph/             # IOC Graph (Operate)
└── threat_feeds/          # Threat Feeds (Operate)
```

Every module uses the same rebuild contract where applicable:

```text
<tool>/
├── __init__.py
├── README.md
├── manifest.py       # mission, capabilities, evidence, integrations
├── engine.py         # canonical implementation adapter
├── api.py            # stable Python/API boundary
├── schemas.py        # evidence/case data structures
├── enrichment.py     # provider plan and status boundary
├── graph.py          # relationship model
├── reporting.py      # exports/report boundary
└── agent.py          # evidence-grounded AI policy
```

`network_artifacts/` keeps its existing deeper structure (`parsers`, `analyzers`, `enrichment`, `correlation`, `incident_response`, `ai`, `reporting`, `workers`) and now also exposes the same module manifest boundary.

`reports/` is a package with backward-compatible exports. The former monolithic `reports.py` implementation is preserved as `report_core.py`, so existing imports continue to work while the report tool has its own rebuild directory.
