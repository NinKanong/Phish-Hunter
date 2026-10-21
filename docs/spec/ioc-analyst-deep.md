# ioc-analyst — Deep Capability Contract

Sections: 10  
Capability fields: 79

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
### IOC OVERVIEW
- IOC value
- IOC type (IP, domain, URL, hash, email, certificate, wallet)
- Defanged value
- Normalized value
- First seen
- Last seen
- Source(s)
- Verdict
### IOC ENRICHMENT
- For every IOC:
- VirusTotal (every engine + result + date)
- [URLScan.io](https://urlscan.io/)
- Google Safe Browsing
- Microsoft SmartScreen
- PhishTank
- OpenPhish
- URLhaus
- Spamhaus
- AlienVault OTX
- AbuseIPDB
- IPQualityScore
- GreyNoise
- MISP (internal)
- OpenCTI (internal)
- WHOIS / RDAP
- DNS records
- Passive DNS
- SSL certificate
- ASN
- Geolocation
- Aggregate verdict
### IOC CORRELATION
- Every related IOC
- Every shared infrastructure
- Every shared certificate
- Every shared favicon
- Every shared ASN
- Every shared nameserver
- Every shared registrant
- Graph visualization
- Verdict
### CONFIDENCE
- Per-source confidence
- Aggregate confidence
- Confidence breakdown
- Verdict
### REPUTATION
- Aggregate reputation score
- Per-source reputation
- Reputation trend over time
- Verdict
### FIRST SEEN / LAST SEEN
- First seen per source
- Last seen per source
- First seen globally
- Last seen globally
- Timeline chart
- Verdict
### RELATED INFRASTRUCTURE
- Every related IP
- Every related domain
- Every related URL
- Every related hash
- Every related certificate
- Every related favicon
- Every related ASN
- Every related nameserver
- Every related registrant
- Graph visualization
### IOC EXPORT
- STIX 2.1 bundle
- MISP event
- OpenIOC
- MAEC
- CSV
- JSON
- YAML
- FireEye IOC
- Every format
### MITRE ATT&CK
- Every technique associated with this IOC
- Verdict
### REPORT
- All sections
- Raw evidence appendix
- 30+ export formats
- Self-verification passed
- ---