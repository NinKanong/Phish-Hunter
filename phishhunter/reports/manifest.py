from __future__ import annotations

TOOL_KEY = 'reports'
DISPLAY_NAME = 'Reports'
MISSION = 'Turn structured analysis evidence into reproducible analyst, executive, forensic, CSV and STIX report packages.'
CAPABILITIES = ['Executive summary', 'Forensic narrative', 'Finding catalog', 'Evidence appendix', 'IOC CSV', 'Connections CSV', 'Markdown', 'HTML', 'JSON', 'STIX bundle', 'PDF export boundary', 'Chain-of-custody digest', 'Report versioning', 'Case metadata', 'Analyst sign-off fields', 'Source citations', 'Uncertainty disclosure', 'Machine-readable bundle']
EVIDENCE_SOURCES = ['all analyst result schemas', 'case records', 'evidence ledger']
INTEGRATIONS = ['Jinja2', 'WeasyPrint', 'ReportLab', 'python-docx', 'openpyxl', 'python-pptx', 'stix2']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
