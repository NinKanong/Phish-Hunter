from __future__ import annotations

TOOL_KEY = 'actors'
DISPLAY_NAME = 'Threat Actors'
MISSION = 'Evidence-backed actor and cluster profiles with explicit uncertainty and no unsupported attribution.'
CAPABILITIES = ['Actor dossier scaffolding', 'Alias and cluster relationships', 'Infrastructure overlaps', 'Malware/tool overlaps', 'TTP/ATT&CK mapping', 'Campaign relationships', 'Targeting-sector notes', 'Time/region context slots', 'Source confidence', 'Conflicting evidence', 'Attribution caveats', 'Case pivots', 'Graph promotion', 'Analyst narrative', 'Report package']
EVIDENCE_SOURCES = ['MISP/OpenCTI', 'ATT&CK', 'public threat reports', 'internal investigations']
INTEGRATIONS = ['MITRE ATT&CK', 'MISP', 'OpenCTI', 'Maltego', 'TheHive', 'Cortex', 'STIX 2.1', 'Graphistry', 'Neo4j']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
