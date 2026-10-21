# ransomware-analyst — Deep Capability Contract

Sections: 19  
Capability fields: 144

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
### SAMPLE ANALYSIS
- Sample identification
- Hashes
- File type
- Packer
- Compiler
- First seen
- Family guess
- Verdict
### RANSOM NOTE ANALYSIS
- Every ransom note extracted
- Every ransom note decoded
- Every ransom note hashed
- Language
- Every payment address (BTC, XMR, etc.)
- Every email address
- Every TOX ID
- Every onion URL
- Every Telegram handle
- Every deadline
- Every threat (leak, DDoS, etc.)
- Every victim-specific data
- Family attribution
- Verdict
### EXTENSION ANALYSIS
- Every file extension appended
- Extension length
- Extension entropy
- Extension pattern
- Family match
- Verdict
### ENCRYPTION BEHAVIOR
- Crypto algorithm (AES, ChaCha20, RSA, ECC)
- Key size
- IV / nonce
- Key generation method
- Key storage (in memory, in file, in registry)
- File targeting (every extension)
- File size thresholds
- Partial encryption (header-only, footer-only, full)
- Ransom note drop location
- Encryption speed
- Verdict
### FILE TARGETING
- Every targeted extension (documents, images, databases, etc.)
- Every targeted folder
- Every excluded folder (system, backup)
- Every excluded extension
- Network share targeting
- Cloud storage targeting
- Verdict
### PROCESS BEHAVIOR
- Every process spawned
- Every command line
- Every parent-child relationship
- Self-deletion
- Process hollowing
- Code injection
- Token manipulation
- Verdict
### PERSISTENCE
- Every registry key modified
- Every scheduled task created
- Every service installed
- Every startup folder entry
- Every WMI event subscription
- Every COM hijack
- Verdict
### SHADOW COPY ACTIVITY
- vssadmin delete shadows
- wbadmin delete catalog
- bcdedit /set recoveryenabled No
- wmic shadowcopy delete
- Every command with full path
- Every command with full arguments
- Verdict
### BACKUP DESTRUCTION
- Every backup service stopped
- Every backup service deleted
- Every backup file deleted
- Every backup share accessed
- Verdict
### C2 INFRASTRUCTURE
- Every C2 server (Tor, I2P, clearnet, Telegram)
- Every C2 protocol
- Every C2 encryption
- Every C2 fallback
- Every C2 config
- Verdict
### IOC EXTRACTION
- Every IP
- Every domain
- Every URL
- Every hash
- Every email
- Every crypto wallet
- Every extension
- Every mutex
- Every registry key
- Verdict
### RANSOMWARE FAMILY
- Family identification
- Family confidence
- Family variant
- Family version
- Family signature
- Family known tools
- Verdict
### THREAT ACTOR / CAMPAIGN
- Actor attribution
- Actor confidence
- Campaign attribution
- Campaign confidence
- Prior victims
- Prior IOCs
- Verdict
### MITRE ATT&CK
- Every technique
- Every technique with evidence
- Verdict
### KILL CHAIN
- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation
- Command & Control
- Actions on Objectives
- Every stage with evidence
### IMPACT ASSESSMENT
- Estimated blast radius (files, folders, shares)
- Estimated downtime
- Estimated data loss
- Estimated recovery cost
- Regulatory impact
- Reputational impact
- Verdict
### EVIDENCE
- Every ransom note
- Every encrypted file sample
- Every registry export
- Every scheduled task XML
- Every process dump
- Every memory dump
- Every network capture
- Verdict
### TIMELINE
- First file encrypted
- Last file encrypted
- Ransom note dropped
- Persistence established
- C2 contacted
- Backup destroyed
- Every event with timestamp
### INCIDENT REPORT
- Executive summary
- Technical findings
- Impact assessment
- Recommendations
- Raw evidence appendix
- 30+ export formats
- Self-verification passed
- ---