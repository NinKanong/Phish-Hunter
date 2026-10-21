# Cyber-Phish-k4 — Ultra-Deep Email Analyst

This document describes the **Email Analyst service only**. The rest of the Cyber-Phish-k4 site is intentionally left unchanged.

## Investigation layers

1. RFC 5322/MIME parsing and message normalization.
2. Received-chain graph construction with hop-to-hop latency measurements.
3. Internal-looking header contradiction heuristics.
4. SPF/DKIM/DMARC/ARC evidence handling without inventing validation.
5. HTML DOM inspection: hidden iframes, CSS cloaking, canvas signals, forms, scripts and external resources.
6. Embedded base64 image inventory with hashes and an explicit OCR-not-run state unless OCR is deployed.
7. Security-gateway wrapper decoding for common Safe Links / URL Defense / Mimecast / Barracuda-style URLs.
8. Static phishing-kit fingerprinting. Labels are pattern matches, not actor attribution.
9. Attachment magic-byte verification, MIME/extension mismatch detection, OLE2/VBA indicators and OOXML inspection.
10. HTML-smuggling heuristics for HTML/JS attachments containing reconstruction primitives.
11. Psychological-pressure scoring for urgency, fear, authority, greed and curiosity using deterministic lexical evidence.
12. MITRE ATT&CK, Cyber Kill Chain, Diamond Model and MITRE D3FEND-oriented mapping.
13. Evidence-first investigation-agent plan with explicit human-confirmation boundaries.
14. Open-source enrichment fabric with a large adapter catalog and capability lanes.

## Scale and connector truthfulness

The fabric is **adapter-ready**, not a fake claim that hundreds of products are already installed or queried. The registry currently contains hundreds of open-source ecosystem profiles and thousands of capability lanes. A profile remains unavailable until a connector is configured.

The runtime follows these rules:

- No provider result is fabricated.
- Unconfigured providers are marked unavailable.
- Connector execution is opt-in/configured.
- External enrichment is isolated from static parsing.
- The application host never detonates an uploaded attachment.

The existing configured threat-intelligence connectors can enrich email-extracted URLs and attachment hashes when enabled.

## Agent

`GET /services/email-analyst/agent` returns the current agent/fabric contract. The agent is deterministic and evidence-first. It produces ordered investigation pivots rather than silently taking containment actions.

Potential containment actions such as mailbox quarantine, firewall blocking, endpoint isolation, credential reset and artifact deletion are represented as human-confirmed follow-up actions only.

## Optional future adapters

The architecture is designed for connectors such as MISP, OpenCTI, TheHive/Cortex, Wazuh, Zeek, Suricata, YARA/ClamAV, CAPE/Cuckoo, parsedmarc and other configured systems. Their results must be normalized before they are shown as evidence.

## Static execution boundary

The Email Analyst does not execute JavaScript, VBA, HTML attachments or binaries on the application host. Headless-browser and sandbox capabilities can be added behind an isolated provider boundary later; static analysis remains safe by default.
