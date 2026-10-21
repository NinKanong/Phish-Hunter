from __future__ import annotations

TOOL_KEY = 'sandbox'
DISPLAY_NAME = 'Sandbox'
MISSION = 'Isolated dynamic-analysis control plane that never detonates untrusted samples inside the web application process.'
CAPABILITIES = ['Provider-agnostic submission boundary', 'Sample hash identity', 'Execution profile manifest', 'Network egress policy hooks', 'Snapshot/revert workflow hooks', 'Process/file/network artifact capture boundary', 'PCAP and DNS artifact capture boundary', 'YARA/Sigma post-processing', 'ATT&CK behavior mapping', 'IOC extraction', 'Detonation evidence ledger', 'Timeout/resource policy', 'Tenant isolation boundary', 'Secret/credential isolation', 'Result normalization', 'IR handoff', 'Case evidence promotion']
EVIDENCE_SOURCES = ['isolated sandbox provider', 'local hash/evidence store', 'post-detonation telemetry']
INTEGRATIONS = ['CAPEv2', 'Cuckoo', 'Any.Run', 'Joe Sandbox', 'Hybrid Analysis', 'VMware', 'VirtualBox', 'Firecracker', 'KVM', 'Velociraptor', 'Zeek', 'Suricata', 'YARA', 'MISP']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
