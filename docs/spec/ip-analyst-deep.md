# ip-analyst — Deep Capability Contract

Sections: 15  
Capability fields: 93

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
### IP OVERVIEW
- IP address (v4 or v6)
- IP range (CIDR)
- IP type (public, private, reserved, multicast, loopback, etc.)
- Reverse DNS (PTR)
- Verdict
### GEOLOCATION
- Country (name + code)
- Region / state
- City
- Postal code
- Latitude / longitude
- Timezone
- Accuracy radius
- Multiple source comparison (MaxMind, IP2Location, DB-IP)
- Verdict
### ASN
- ASN number
- ASN name
- ASN country
- ASN organization
- ASN reputation
- ASN malicious ratio
- ASN type (hosting, ISP, education, government, business)
- ASN peers
- Verdict
### HOSTING
- Hosting provider
- Hosting type (cloud, VPS, dedicated, shared, bulletproof)
- Bulletproof hosting score
- Abuse contact
- Abuse email
- Reporting history
- Verdict
### REVERSE DNS
- PTR record
- Forward confirmation
- Mismatch check
- Verdict
- OPEN SERVICES (deep, via Shodan/Censys)
- Every open port
- Every service banner
- Every service version
- Every SSL cert
- Every technology
- Verdict
### PORTS
- Every open port
- Every filtered port
- Every closed port
- Port scan history
- Verdict
### REPUTATION
- AbuseIPDB (score, reports, last report)
- IPQualityScore (risk score, fraud score)
- GreyNoise (classification, last seen)
- VirusTotal (detections)
- Spamhaus (blocklist status)
- SORBS
- Barracuda
- CINS
- UCEPROTECT
- Aggregate verdict
### ABUSE REPORTS
- Every report (source, date, category, comment)
- Report trends (timeline)
- Reporting organizations
- Verdict
### RELATED DOMAINS
- Every domain ever pointing to this IP
- Every domain with same ASN
- Passive DNS history
- First/last seen per domain
- Verdict
### RELATED CERTIFICATES
- Every certificate issued for this IP
- Every certificate with this IP as SAN
- Certificate issues
- Verdict
### HISTORICAL ACTIVITY
- First seen
- Last seen
- Historical ASN
- Historical geolocation
- Historical reputation
- Traffic patterns
- Verdict
### IOC CORRELATION
- Every IOC associated with this IP
- Every report referencing this IP
- Every campaign using this IP
- Every actor using this IP
- Verdict
### MITRE ATT&CK
- Every technique associated with this IP's activity
- Verdict
### RISK SCORE
- Score 0-100
- Verdict
- Confidence
- Every signal with weight + contribution
- Explanation
### REPORT
- All sections
- Raw evidence appendix
- 30+ export formats
- Self-verification passed
- ---