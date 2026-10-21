from __future__ import annotations

TOOL_KEY = 'feeds'
DISPLAY_NAME = 'Threat Feeds'
MISSION = 'Ingest, validate, normalize and operationalize threat feeds into a provenance-preserving intelligence layer.'
CAPABILITIES = ['CSV/JSON/line-delimited feed parsing', 'STIX-like normalization', 'Indicator de-duplication', 'Source metadata', 'Confidence/severity normalization', 'First/last-seen fields', 'TTL/freshness handling', 'Malicious/benign/unknown disposition', 'Feed health metrics', 'IOC promotion', 'Graph promotion', 'Detection export boundary', 'MISP publication boundary', 'OpenCTI ingestion boundary', 'Analyst review queue', 'Error quarantine']
EVIDENCE_SOURCES = ['vendor feeds', 'open feeds', 'MISP', 'OpenCTI', 'URLhaus', 'ThreatFox', 'OTX']
INTEGRATIONS = ['MISP', 'OpenCTI', 'URLhaus', 'ThreatFox', 'AlienVault OTX', 'Spamhaus', 'Abuse.ch', 'Feodo Tracker', 'CISA KEV', 'MalwareBazaar', 'GreyNoise']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
