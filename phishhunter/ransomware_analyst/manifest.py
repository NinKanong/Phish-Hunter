from __future__ import annotations

TOOL_KEY = 'ransomware-analyst'
DISPLAY_NAME = 'Ransomware Analyst'
MISSION = 'Defensive ransomware triage from notes and samples through indicators, impact clues, ATT&CK mappings and containment actions.'
CAPABILITIES = ['Ransom-note language and artifact triage', 'Sample/file hashing', 'File extension and naming patterns', 'Encryption/process behavior signal hooks', 'Shadow-copy/backup deletion indicators', 'Credential/access tooling signals', 'SMB/network propagation clues', 'Scheduled task/service indicators', 'Registry/persistence signal hooks', 'IOC extraction', 'Known ransomware family enrichment slots', 'MITRE ATT&CK mapping', 'Victim/asset impact notes', 'Containment checklist', 'Credential reset decision support', 'Hunt query generation boundary', 'Evidence timeline', 'Confidence and uncertainty', 'Incident report packaging']
EVIDENCE_SOURCES = ['artifact text', 'file metadata', 'EDR/SIEM telemetry connectors', 'MISP/OpenCTI', 'ATT&CK']
INTEGRATIONS = ['YARA', 'Sigma', 'Kusto/Sentinel', 'Splunk', 'Elastic', 'Wazuh', 'Velociraptor', 'osquery', 'MISP', 'OpenCTI', 'VirusTotal', 'Malpedia', 'MITRE ATT&CK']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
