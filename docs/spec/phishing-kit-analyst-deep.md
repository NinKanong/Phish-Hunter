# phishing-kit-analyst — Deep Capability Contract

Sections: 12  
Capability fields: 105

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
### KIT IDENTIFICATION
- Kit name (if known)
- Kit version
- Kit family (16Shop, Monkey, LogoKit, Caffeine, XBAP, etc.)
- Kit fingerprint (HTML structure, JS structure, file paths)
- Kit confidence
- Kit source (if available on GitHub/pastebin)
- Verdict
### HTML ANALYSIS
- Full raw HTML
- Sanitized HTML
- Every tag
- Every form
- Every input
- Every hidden field
- Every CSS rule (hidden text, offscreen, tiny fonts)
- Every JavaScript reference
- Every external resource
- Obfuscation techniques
- Verdict
### JAVASCRIPT ANALYSIS
- Full AST
- Every eval / Function / setTimeout / setInterval
- Every obfuscation layer peeled
- Every network call
- Every DOM manipulation
- Every crypto operation
- Every form grab
- Every keyboard event listener
- Every clipboard operation
- Detected kit behavior
- Verdict
### CREDENTIAL FORM DETECTION
- Every form
- Action URL
- Method
- Every field (name, type, placeholder, required, pattern)
- Password fields
- Email fields
- OTP fields
- Credit card fields
- Hidden fields (with values)
- Multi-step form detection
- Form validation rules
- Where the form submits (attacker panel)
- Verdict
### BRAND DETECTION
- Every brand matched
- SSIM score
- Favicon mmh3
- Logo detection
- Title match
- Copyright text match
- Layout similarity
- Color palette similarity
- Wording similarity
- Verdict
### OBFUSCATION DETECTION
- HTML entities
- JS escapes
- Base64
- ROT13
- XOR
- Unicode escapes
- String array rotation
- Dead code injection
- Anti-debug
- Anti-VM
- Verdict
### IOC EXTRACTION
- Every URL (defanged)
- Every domain (defanged)
- Every IP (defanged)
- Every email
- Every Telegram bot token
- Every Discord webhook
- Every Slack webhook
- Every Bitcoin wallet
- Every panel URL
- Every exfil endpoint
- Verdict
### INFRASTRUCTURE MAPPING
- Every server
- Every CDN
- Every panel URL
- Every exfil endpoint
- Every redirect chain
- Every SSL certificate
- Every ASN
- Every geolocation
- Verdict
### CAMPAIGN CORRELATION
- Every related campaign
- Every related actor
- Every shared IOC
- Every shared infrastructure
- Graph visualization
- Verdict
### MITRE ATT&CK
- T1566.002 Spearphishing Link
- T1204.001 User Execution: Malicious Link
- T1583.001 Acquire Infrastructure: Domains
- T1585.002 Establish Accounts: Email Accounts
- T1071.001 Application Layer Protocol: Web Protocols
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