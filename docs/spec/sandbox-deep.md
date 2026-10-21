# sandbox — Deep Capability Contract

Sections: 10  
Capability fields: 66

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
### SANDBOX OVERVIEW
- Sandbox name (CAPEv2, ANY.RUN, Joe, Hybrid, VMRay, Triage)
- Task ID
- Status
- Queue position
- Estimated time
- Verdict
### SUBMISSION
- Sample (file or URL)
- Options (timeout, machine, network, etc.)
- Submission timestamp
- Submission response
- Verdict
### EXECUTION
- Every process spawned (name, PID, PPID, cmdline, integrity)
- Every file touched (create/write/delete + path + hash)
- Every registry key touched
- Every network connection (IP, port, protocol, bytes)
- Every DNS query
- Every HTTP request/response
- Every TLS session
- Every mutex created
- Every service installed
- Every scheduled task created
- Every screenshot (with timestamp)
- Every memory dump with secrets
- Anti-VM / anti-debug events
- Verdict per event
### NETWORK CAPTURE
- Full PCAP (linked to PCAP ANALYST)
- Every connection
- Every DNS query
- Every HTTP request
- Every TLS session
- Every C2 callback
- Verdict
### CONFIG EXTRACTION
- Every family-specific config
- Every C2 server
- Every encryption key
- Every bot token
- Every campaign ID
- Verdict
### ANTI-EVASION
- Anti-VM checks (VMware, VirtualBox, Hyper-V, QEMU)
- Anti-debug checks
- Anti-sandbox checks
- Timing checks
- Sleep skipping
- Multi-round detonation
- Verdict per technique
### MULTI-STAGE FOLLOW-UP
- Every dropped file re-analyzed
- Every C2 payload downloaded
- Every lateral movement
- Verdict
### IOC EXTRACTION
- Every IP
- Every domain
- Every URL
- Every hash
- Every mutex
- Every registry key
- Every file path
- Every wallet
- Verdict
### MITRE ATT&CK
- Every technique observed
- Every technique with evidence
- Verdict
### REPORT
- All sections
- Raw evidence appendix
- 30+ export formats
- Self-verification passed
- ---