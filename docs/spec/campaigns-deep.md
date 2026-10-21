# campaigns — Deep Capability Contract

Sections: 7  
Capability fields: 44

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
### CAMPAIGN OVERVIEW
- Campaign ID
- Campaign name
- Campaign description
- Campaign type (phishing, malware, ransomware, BEC, etc.)
- First seen
- Last seen
- Status (active, dormant, closed)
- Confidence
- Verdict
### CAMPAIGN IOCs
- Every IP
- Every domain
- Every URL
- Every hash
- Every email
- Every certificate
- Every favicon
- Every ASN
- Every mutex
- Every registry key
- Verdict per IOC
### CAMPAIGN TTPs
- Every MITRE technique
- Every technique with evidence
- Every tool
- Every infrastructure pattern
- Verdict
### CAMPAIGN VICTIMS
- Every victim (if available)
- Every victim sector
- Every victim country
- Every victim size
- Verdict
### CAMPAIGN TIMELINE
- Every event chronologically
- Every evolution
- Every infrastructure change
- Verdict
### CAMPAIGN ATTRIBUTION
- Actor attribution
- Actor confidence
- Prior campaigns by same actor
- Shared infrastructure
- Verdict
### CAMPAIGN REPORT
- All sections
- Raw evidence appendix
- 30+ export formats
- Self-verification passed
- ---