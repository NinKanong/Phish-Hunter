# domain-analyst — Deep Capability Contract

Sections: 16  
Capability fields: 151

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
### DOMAIN OVERVIEW
- Domain name
- FQDN
- Registered domain
- Subdomain depth
- Length
- Entropy
- Punycode decode
- IDN homoglyph check
- Mixed-script check
- Typosquatting check (Levenshtein, keyboard-adjacent, homophone,
- │ bitsquatting, vowel-swap, TLD-swap, hyphenation, plural, omission)
- Lookalike brand matches (top 20)
- Verdict
### WHOIS / RDAP
- Registrar
- Registrar URL
- Registrar IANA ID
- WHOIS server
- Creation date
- Updated date
- Expiration date
- Domain age (days)
- Registrant name / org / email / phone / address (if public)
- Admin contact
- Tech contact
- Name servers (every one with IP)
- DNSSEC status
- Status codes (clientTransferProhibited, etc.)
- Privacy protection (yes/no + provider)
- Historical WHOIS changes (every change with date)
- Verdict
### DNS RECORDS
- For EVERY record type:
- A (every IP with TTL + first/last seen)
- AAAA (every IP with TTL + first/last seen)
- CNAME (every target)
- MX (every server with priority + IP)
- NS (every server with IP)
- TXT (every value — SPF, DKIM, DMARC, verification, etc.)
- SOA (every field)
- PTR (every reverse)
- SRV (every service)
- CAA (every issuer)
- NAPTR
- DNSKEY / DS / RRSIG (DNSSEC)
- TLSA
- SSHFP
- HINFO
- ANY (if allowed)
### DNS SECURITY
- DNSSEC validation
- DNSKEY presence
- DS record at parent
- RRSIG signatures
- NSEC / NSEC3 records
- Chain of trust validation
- Zone walking possible
- Verdict
### PASSIVE DNS
- Every historical A record (with first/last seen)
- Every historical AAAA record
- Every historical MX record
- Every historical NS record
- Every historical TXT record
- Every IP ever associated
- Timeline of changes
- Fast-flux detection
- IP rotation patterns
- Verdict
### SUBDOMAINS
- Every subdomain discovered (crt.sh, passive DNS, brute-force)
- Every subdomain with A record
- Every subdomain with response code
- Every subdomain with title
- Every subdomain with screenshot (if resolvable)
- Wildcard detection
- Subdomain takeover risk
- Verdict per subdomain
### CERTIFICATE TRANSPARENCY
- Every certificate ever issued
- Every SAN
- Every issuer
- Every validity window
- Every CT log entry
- Every related domain (via SAN)
- Verdict
### IP ASSOCIATIONS
- Every IP ever associated
- Every IP with ASN
- Every IP with geolocation
- Every IP with hosting provider
- Every IP with reverse DNS
- Every IP with open ports
- Reverse IP neighbors (up to 100)
- Verdict
### CERTIFICATE ASSOCIATIONS
- Every certificate ever issued
- Every certificate issuer
- Every certificate SAN
- Shared certificate neighbors (up to 100)
- Verdict
### RELATED DOMAINS
- Same registrant
- Same nameservers
- Same MX
- Same IP
- Same certificate
- Same favicon
- Same analytics ID
- Same Google AdSense ID
- Same Cloudflare account
- Verdict
### REPUTATION
- VirusTotal domain report
- [URLScan.io](https://urlscan.io/) reports
- Google Safe Browsing
- Microsoft SmartScreen
- PhishTank
- OpenPhish
- URLhaus
- Spamhaus
- Cisco Talos
- AlienVault OTX
- IPQualityScore
- GreyNoise
- MISP (internal)
- OpenCTI (internal)
- Aggregate verdict
### BRAND / TYPOSQUATTING
- Every brand match
- Levenshtein distance
- Homoglyph analysis
- Mixed-script analysis
- Hyphenation pattern
- TLD swap
- Vowel swap
- Bit-squatting
- Plural/singular
- Omission/insertion
- Verdict per match
### IOC EXTRACTION
- Every IP
- Every subdomain
- Every URL
- Every email
- Every certificate hash
- Every favicon hash
- Deduplicated + sorted
### MITRE ATT&CK
- T1583.001 Acquire Infrastructure: Domains
- T1585.002 Establish Accounts: Email Accounts
- T1071.001 Application Layer Protocol: Web Protocols
- T1071.004 Application Layer Protocol: DNS
- Every applicable technique with evidence
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