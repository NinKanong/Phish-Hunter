# pcap-analyst — Deep Capability Contract

Sections: 4  
Capability fields: 67

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
### CAPTURE METADATA
- File format (pcap, pcapng, cap, snoop, 5views)
- Interface list (every one)
- Snap length
- Link type
- First packet timestamp (raw + UTC)
- Last packet timestamp (raw + UTC)
- Duration
- Total packets
- Total bytes
- Average packet size
- Packet size histogram (per size bucket: 0-64, 65-128, ..., 1500+)
- Capture comment (if any)
- OS (if in pcapng)
- Application (if in pcapng)
- Verdict
### PROTOCOL HIERARCHY
- For EVERY protocol:
- Packet count
- Byte count
- Percentage
- Sub-protocols
- Anomalies
- Verdict
### CONVERSATIONS
- For EVERY 5-tuple:
- Src IP + port
- Dst IP + port
- Protocol
- Packet count (each direction)
- Byte count (each direction)
- First packet
- Last packet
- Duration
- Packets/second
- Bytes/second
- TCP flags summary
- State
- Suspicion score
- Verdict
### ENDPOINTS
- For EVERY IP:
- IP
- Packets sent
- Packets received
- Bytes sent
- Bytes received
- Geolocation
- ASN
- WHOIS org
- Reverse DNS
- Reputation
- Suspicion
- Verdict
- DNS (deep) — every query with 15+ fields (already listed)
- HTTP (deep) — every request/response with 20+ fields (already listed)
- TLS (deep) — every session with 30+ fields (already listed)
- TCP (deep) — every stream with 15+ fields (already listed)
- FILE CARVING — every carved file with type-specific extraction
- BEACONING DETECTION — every beacon with 15+ fields
- DGA DETECTION — every DGA candidate with 10+ fields
- DNS TUNNELING — every tunnel with 12+ fields
- LATERAL MOVEMENT — every lateral movement with 10+ fields
- CREDENTIAL EXTRACTION — every credential with 12+ fields (redacted)
- FINGERPRINTS — JA3, JA3S, JA4, JA4S, JA4H, JA4X, HASSH, HASSHServer, p0f
- NETWORK GRAPH — force-directed graph with nodes + edges
- TIMELINE — every event
- MITRE ATT&CK — every technique at PCAP level
- RISK SCORE — explainable
- REPORT — all sections + raw evidence appendix
- ---