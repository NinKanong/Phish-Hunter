# feeds — Deep Capability Contract

Sections: 6  
Capability fields: 107

## Universal requirements
### Evidence
- raw evidence
- interpretation
- source reference
- first seen / last seen
### Confidence
- 0-100 calibrated confidence
- confidence rationale
### Threat Intelligence
- configured-provider lookups
- lookup timestamps
- provider status
### Timeline
- event timestamp
- observation timestamp
- first/last seen
### Correlation
- related findings
- related IOCs
- graph pivot identifiers
### MITRE ATT&CK
- technique ID
- technique name
- evidence reference
- confidence
### Reporting
- raw evidence appendix
- machine-readable result
- analyst report
- self-verification

## Deep sections
### FEED OVERVIEW
- Total feeds
- Total records
- Last update
- Update frequency
- Verdict
### FEED LIST
- For EVERY feed:
- Feed name (PhishTank, OpenPhish, URLhaus, MalwareBazaar, etc.)
- Feed type (phishing, malware, ransomware, etc.)
- Feed URL
- Feed format (JSON, CSV, XML, STIX, TAXII)
- Feed authentication
- Feed update frequency
- Feed last update
- Feed record count
- Feed new records (delta)
- Feed quality score
- Verdict per feed
### FEED INGESTION
- Every record ingested
- Every record deduplicated
- Every record enriched
- Every record timestamped
- Every record with source
- Verdict
### FEED CORRELATION
- Every record cross-referenced with internal data
- Every record linked to campaigns
- Every record linked to actors
- Verdict
### FEED REPORT
- Feed summary
- Feed trends
- Feed quality
- Raw evidence appendix
- 30+ export formats
- Self-verification passed
- ---
### # PART 3 — UPDATED FULL CODE STRUCTURE
- Add these to the tree from the v3 prompt:
- cyber_phish_k4/
- ─ analyzers/
- ─ email/ # 40+ files
- ─ url/ # 35+ files
- ─ file/ # 70+ files
- ─ domain/ # 15+ files
- ─ ip/ # 15+ files
- ─ pcap/ # 70+ files
- ─ malware/ # 15+ files
- ─ ransomware/ # 20+ files
- ─ ioc/ # 10+ files
- ─ phishing_kit/ # 12+ files
- ─ threat_intelligence/ # 12+ files
- ─ common/
- ─ ioc_extract.py
- ─ defang.py
- ─ normalize.py
- ─ validators.py
- ─ scoring_helpers.py
- ─ entropy_helpers.py
- ─ evidence.py # NEW: raw evidence capture
- ─ mitre_map.py # NEW: MITRE mapping helper
- ─ confidence.py # NEW: confidence scoring
- ─ timeline.py # NEW: timeline builder
- │
- ─ reports/
- ─ builder.py
- ─ renderer.py
- ─ postprocess.py
- ─ evidence_appendix.py # NEW: raw evidence appendix builder
- ─ exporters/ # 100+ files
- ─ templates/
- ─ base_report.html.j2
- ─ sections/ # 60+ sections
- ─ styles/
- │
- ─ tasks/
- ─ email_tasks.py
- ─ url_tasks.py
- ─ file_tasks.py
- ─ domain_tasks.py
- ─ ip_tasks.py
- ─ pcap_tasks.py
- ─ malware_tasks.py
- ─ ransomware_tasks.py
- ─ ioc_tasks.py
- ─ phishing_kit_tasks.py
- ─ threat_intelligence_tasks.py
- ─ sandbox_tasks.py
- ─ enrichment_tasks.py
- ─ ai_tasks.py
- ─ report_tasks.py
- ─ report_export_tasks.py
- ─ report_schedule_tasks.py
- ─ notification_tasks.py
- ─ feed_tasks.py
- ─ integration_tasks.py
- ─ status_tasks.py
- ─ guest_tasks.py
- ─ maintenance_tasks.py
- │
- ─ workers/ # matching worker files for every task
- │
- ─ services/ # matching service files for every analyzer
- │
- ─ models/ # matching models for every analyzer
- │
- ─ schemas/ # matching schemas for every analyzer
- │
- ─ api/v1/ # matching API routes for every analyzer
- │
- ─ web/routes/ # matching web routes for every analyzer