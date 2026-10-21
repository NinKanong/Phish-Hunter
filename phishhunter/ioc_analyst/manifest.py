from __future__ import annotations

TOOL_KEY = 'ioc-analyst'
DISPLAY_NAME = 'IOC Analyst'
MISSION = 'Normalize, classify, enrich, correlate and operationalize mixed indicators without losing provenance.'
CAPABILITIES = ['URL/domain/IP/hash/email extraction', 'Defang/refang normalization', 'Indicator canonicalization', 'Type/confidence classification', 'Duplicate clustering', 'Cross-indicator correlation', 'Threat-intel enrichment slots', 'Graph relationship modeling', 'Campaign clustering hooks', 'Detection query generation boundary', 'Watchlist/export support', 'STIX 2.1 packaging boundary', 'Evidence source tracking', 'First/last-seen timeline slots', 'Risk scoring', 'False-positive notes', 'Analyst pivot queue', 'Case promotion', 'IR action handoff']
EVIDENCE_SOURCES = ['user evidence', 'MISP', 'OpenCTI', 'VirusTotal', 'urlscan.io', 'ThreatFox', 'URLhaus', 'OTX', 'local datasets']
INTEGRATIONS = ['MISP', 'OpenCTI', 'VirusTotal', 'ThreatFox', 'URLhaus', 'AlienVault OTX', 'AbuseIPDB', 'GreyNoise', 'urlscan.io', 'Cortex', 'TheHive', 'Sigma', 'YARA', 'STIX 2.1']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
