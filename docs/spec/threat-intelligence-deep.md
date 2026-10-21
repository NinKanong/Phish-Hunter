# threat-intelligence — Deep Capability Contract

Sections: 9  
Capability fields: 58

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
### THREAT INTEL OVERVIEW
- Total IOCs tracked
- Total campaigns
- Total actors
- Total feeds
- Total sources
- Verdict
### IOC CORRELATION
- Every IOC
- Every related IOC
- Every relationship type
- Every confidence level
- Graph visualization
- Verdict
### MALWARE
- Every malware family
- Every family with IOCs
- Every family with TTPs
- Every family with campaign
- Every family with actor
- Verdict per family
### CAMPAIGN TRACKING
- Every campaign
- Every campaign with IOCs
- Every campaign with TTPs
- Every campaign with actor
- Every campaign timeline
- Every campaign victim
- Verdict per campaign
### THREAT ACTOR
- Every actor
- Every actor with aliases
- Every actor with TTPs
- Every actor with campaigns
- Every actor with IOCs
- Every actor with targets
- Every actor with attribution confidence
- Verdict per actor
### RELATIONSHIP GRAPH
- Every entity (IOC, campaign, actor, malware, TTP)
- Every relationship
- Every relationship confidence
- Every relationship source
- Interactive graph (Cytoscape)
- Verdict
### FEED INGESTION
- Every feed (PhishTank, OpenPhish, URLhaus, etc.)
- Every feed with update frequency
- Every feed with record count
- Every feed with last update
- Every feed with new records (delta)
- Every feed with reputation
- Verdict per feed
### INTEGRATION
- Push to MISP
- Push to OpenCTI
- Push to SIEM (Splunk, Sentinel, QRadar)
- Push to SOAR (Cortex XSOAR, Tines, Torq)
- Push to ticketing (Jira, ServiceNow)
- Every push with status + timestamp
- Verdict
### REPORT
- All sections
- Raw evidence appendix
- 30+ export formats
- Self-verification passed
- ---