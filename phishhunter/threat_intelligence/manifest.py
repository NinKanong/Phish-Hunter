from __future__ import annotations

TOOL_KEY = 'threat-intelligence'
DISPLAY_NAME = 'Threat Intelligence'
MISSION = 'Correlate indicators with external and internal intelligence sources while preserving source, confidence and freshness.'
CAPABILITIES = ['IOC enrichment', 'Source confidence scoring', 'First/last seen timeline', 'Campaign relationship hooks', 'Malware family pivots', 'Threat-actor relationship hooks', 'Infrastructure pivots', 'Sector/geography context slots', 'TTP/ATT&CK mapping', 'MISP/OpenCTI relationship ingestion', 'Reputation and abuse signals', 'Historical evidence slots', 'Freshness/TTL tracking', 'Conflicting-source handling', 'Analyst notes', 'Evidence provenance', 'Graph promotion', 'Case handoff', 'Feed watch hooks']
EVIDENCE_SOURCES = ['MISP', 'OpenCTI', 'VirusTotal', 'AbuseIPDB', 'GreyNoise', 'OTX', 'ThreatFox', 'URLhaus', 'urlscan.io', 'internal telemetry']
INTEGRATIONS = ['MISP', 'OpenCTI', 'Cortex', 'TheHive', 'VirusTotal', 'GreyNoise', 'AlienVault OTX', 'ThreatFox', 'URLhaus', 'AbuseIPDB', 'Recorded Future', 'Anomali', 'CrowdStrike Intel', 'Microsoft TI']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
