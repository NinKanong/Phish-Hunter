from __future__ import annotations

TOOL_KEY = 'email-analyst'
DISPLAY_NAME = 'Email Analyst'
MISSION = 'Deep email forensics from raw message to sender infrastructure, authentication, payloads, IOCs and response actions.'
CAPABILITIES = ['MIME and multipart tree', 'Received-hop reconstruction', 'Header chronology and routing anomalies', 'SPF/DKIM/DMARC/ARC validation evidence', 'From/Reply-To/Return-Path alignment', 'HTML DOM and visible-text inspection', 'Tracking pixel and remote resource inventory', 'URL normalization and redirect pivots', 'Attachment inventory and hashes', 'Embedded object and archive triage', 'IOC extraction and normalization', 'Threat-intel enrichment slots', 'Phishing-language and impersonation signals', 'Evidence provenance and confidence', 'MITRE ATT&CK mapping', 'IR disposition and containment tasks', 'Analyst timeline reconstruction', 'Export-ready case package']
EVIDENCE_SOURCES = ['RFC 5322 headers', 'Authentication-Results', 'DNS TXT/NS/MX', 'Certificate Transparency', 'URL scanners', 'Threat-intelligence APIs', 'Local parser evidence']
INTEGRATIONS = ['mailparser', 'emldump', 'oledump', 'ripmime', 'SpamAssassin', 'Rspamd', 'urlscan.io', 'VirusTotal', 'MISP', 'OpenCTI', 'YARA', 'LIEF', 'Apache Tika']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
