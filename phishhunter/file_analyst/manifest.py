from __future__ import annotations

TOOL_KEY = 'file-analyst'
DISPLAY_NAME = 'File Analyst'
MISSION = 'Evidence-preserving static triage of suspicious files before deeper malware or sandbox workflows.'
CAPABILITIES = ['Magic-byte identification', 'MIME/type mismatch detection', 'MD5/SHA1/SHA256/SHA512 hashing', 'Entropy profiling', 'Strings and IOC extraction', 'PE/ELF/Mach-O structural triage', 'Document metadata and macro signals', 'Archive/container inventory', 'Embedded payload discovery', 'YARA rule matching boundary', 'Suspicious API/import indicators', 'Signer and certificate metadata', 'Static packer indicators', 'DNS/URL/email extraction', 'Reputation enrichment slots', 'Evidence chain and hash ledger', 'Risk scoring', 'Analyst pivot recommendations', 'Report-ready artifact profile']
EVIDENCE_SOURCES = ['libmagic/file signatures', 'PE/ELF/document metadata', 'YARA', 'local parser output', 'threat-intel providers']
INTEGRATIONS = ['YARA', 'LIEF', 'pefile', 'oletools', 'oledump', 'pdfid', 'pdf-parser', '7-Zip', 'ExifTool', 'TrID', 'capa', 'Detect It Easy', 'ClamAV', 'VirusTotal', 'MISP', 'OpenCTI']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
