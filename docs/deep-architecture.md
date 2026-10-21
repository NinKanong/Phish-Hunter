# Cyber-Phish-k4 Deep Analyst Architecture

This release implements the supplied Universal Depth Rules as an explicit runtime contract.

## Evidence contract

Every finding has:

- a finding ID
- a human-readable description
- raw evidence IDs
- interpretation
- confidence 0-100
- severity
- first/last seen
- related IOCs
- threat-intelligence status
- optional MITRE ATT&CK evidence

The system never fabricates provider results. If an external connector is not configured, the report records that the lookup was not performed and why.

## Service isolation

Every analyst has a dedicated workspace route and a service capability manifest. Analysis engines are independent from presentation and reporting. A normalized result is passed through the universal depth enhancer before persistence and export.

## PCAP

The passive network engine provides capture metadata, protocol hierarchy, flows, endpoints, DNS, HTTP metadata, TLS SNI, host profiles, potential compromised-host candidates, potential C2 candidates, external-source candidates, beaconing candidates, DGA candidates, DNS-tunneling candidates and lateral-movement candidates. These are evidence-driven hypotheses and are not proof of compromise or attribution.

## Dynamic analysis boundary

Uploaded malware is not executed by the web application. Sandbox integration is an adapter boundary for an isolated execution provider.

## Reporting

The reporting suite supports PDF, HTML, DOCX, XLSX, PPTX, JSON, JSON-LD, XML, YAML, CSV, TSV, STIX 2.1, MISP, OpenIOC, MAEC, SARIF, VERIS, YARA, Sigma, Suricata, Snort, Zeek, KQL, SPL, AQL, EQL, blocklists, GraphML, GEXF, DOT, Mermaid, MITRE Navigator, D3FEND, Kill Chain, Diamond Model, CycloneDX, SPDX, OpenAPI, Postman, Slack, Teams, Discord, Telegram and webhook payloads, plus a complete ZIP bundle.

## Self verification

The result contract verifies evidence links and numeric confidence before a report is finalized.


## K4 v12 IR Workbench
The Network Artifacts workspace now includes an interactive attack graph, victim/endpoint pivots, kill-chain timeline, bounded packet-level forensic drill-down, C2/beaconing analysis, exfiltration tracking, DNS intelligence, threat-intelligence evidence ledger, response blocklist generation, analyst disposition notes, chain-of-custody metadata, and executive/forensic reporting. The analysis remains passive and attribution is explicitly treated as a hypothesis requiring corroboration.
