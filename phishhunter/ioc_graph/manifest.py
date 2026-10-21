from __future__ import annotations

TOOL_KEY = 'graph'
DISPLAY_NAME = 'IOC Graph'
MISSION = 'Interactive relationship analysis across indicators, infrastructure, artifacts, campaigns, actors and cases.'
CAPABILITIES = ['Typed nodes and edges', 'Evidence-backed relationships', 'Domain/IP/certificate pivots', 'Email/file/URL/PCAP relationships', 'Campaign and actor clusters', 'Shortest-path exploration', 'Neighbor expansion hooks', 'Confidence on relationships', 'Time-aware edges', 'Case scoping', 'Isolated node inspection', 'Graph export', 'STIX graph boundary', 'Analyst notes', 'Relationship provenance']
EVIDENCE_SOURCES = ['all analyst modules', 'MISP', 'OpenCTI', 'Neo4j/graph backends']
INTEGRATIONS = ['Neo4j', 'Graphistry', 'Maltego', 'OpenCTI', 'MISP', 'Gephi', 'Cytoscape', 'STIX 2.1']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
