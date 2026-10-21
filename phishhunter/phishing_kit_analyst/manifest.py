from __future__ import annotations

TOOL_KEY = 'phishing-kit-analyst'
DISPLAY_NAME = 'Phishing Kit Analyst'
MISSION = 'Static inspection of phishing-site kits, archive payloads, lures and infrastructure relationships for defensive response.'
CAPABILITIES = ['Archive and bundle inventory', 'HTML/JS/static asset inspection', 'Brand/keyword and form analysis', 'Credential-post destination mapping', 'Embedded URL/domain/IP extraction', 'Obfuscation indicators', 'Base64/encoded asset indicators', 'JavaScript redirection clues', 'Kit reuse/fingerprint hooks', 'Certificate/domain pivoting', 'Hosting/infrastructure relations', 'IOC extraction', 'Evidence screenshots boundary', 'Campaign clustering hooks', 'ATT&CK mapping', 'Take-down evidence preparation', 'Detection content boundary', 'Risk scoring', 'Chain of custody', 'Case report']
EVIDENCE_SOURCES = ['uploaded kit/archive', 'HTML/JS parsers', 'DNS/CT', 'urlscan.io', 'VirusTotal', 'MISP/OpenCTI']
INTEGRATIONS = ['YARA', 'Semgrep', 'js-beautify', 'esprima', 'BeautifulSoup', 'urlscan.io', 'VirusTotal', 'MISP', 'OpenCTI', 'Wayback Machine', 'Maltego', 'SpiderFoot']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
