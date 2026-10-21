from __future__ import annotations

TOOL_KEY = 'campaigns'
DISPLAY_NAME = 'Campaigns'
MISSION = 'Cluster evidence-backed indicators and observations into campaign-level investigations without unsupported attribution.'
CAPABILITIES = ['IOC clustering', 'Infrastructure overlap analysis', 'Shared certificate/registrar/NS/hosting signals', 'Temporal clustering', 'Lure/theme clustering', 'Malware overlap hooks', 'TTP overlap', 'Victim-sector context', 'Confidence ladder', 'Campaign timeline', 'Related cases', 'Graph generation', 'Analyst notes', 'Evidence-backed attribution boundary', 'Detection/hunt task handoff', 'Report packaging']
EVIDENCE_SOURCES = ['IOC evidence', 'case records', 'threat feeds', 'domain/IP/URL analysts', 'PCAP/email/file telemetry']
INTEGRATIONS = ['MISP', 'OpenCTI', 'Maltego', 'SpiderFoot', 'TheHive', 'Cortex', 'STIX 2.1', 'MITRE ATT&CK', 'Graphistry', 'Neo4j']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
