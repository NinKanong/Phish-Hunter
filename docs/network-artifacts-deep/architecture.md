# K4 Network Artifacts Deep Investigation Architecture

This subsystem is the PCAP Analyst / Network Artifacts sibling workspace. It is intentionally isolated from the other Cyber-Phish-k4 analyst services.

## Evidence flow

Upload -> validation -> SHA-256 identity -> artifact classification -> passive parser -> normalized events -> protocol/file analysis -> correlation -> behavioral detections -> identity/asset profiling -> enrichment boundary -> MITRE candidate mapping -> incident-response workflow -> timeline -> graph -> HTML/PDF/JSON/CSV/STIX report.

## Supported evidence families

- PCAP / PCAPNG / CAP
- Zeek TSV logs (connection, DNS, HTTP, TLS/SSL, SMB, Kerberos when fields are present)
- Suricata EVE JSON
- NetFlow/IPFIX CSV/JSON
- Firewall / proxy / DNS / DHCP logs

## PCAP deep analysis

The local parser is dependency-light and bounded. It parses Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP metadata, DNS questions/answers, HTTP metadata and TLS SNI. A second deep pass reconstructs bounded TCP byte streams, runs protocol dissection, and performs best-effort signature-based passive file carving. Every uploaded artifact and extracted file candidate receives MD5/SHA-1/SHA-256/SHA-512 where applicable.

The reassembler is deliberately not marketed as a full Wireshark/Arkime replacement: retransmission ordering, TCP evasion normalization, decryption, and arbitrary protocol decoding require specialized external engines. The report exposes these limitations instead of fabricating results.

## Incident response

The report follows a defensive incident-response lifecycle: preparation, detection/triage, containment planning, evidence collection, analysis, eradication planning, recovery planning, and lessons learned. The system does not automatically isolate hosts, block IPs, exploit systems, or execute recovered files.

## AI agent boundary

`NetworkArtifactAgentController` is deterministic and evidence-first. It exposes stages, memory, questions and decisions. It can be adapted to LangGraph/Temporal/LangChain deployments without making an LLM a prerequisite for core parsing. An LLM must not be allowed to invent evidence; all narrative statements should be grounded in stored observations.
