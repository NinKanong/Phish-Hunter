from phishhunter.analysis.depth_contract import capability_manifest

SERVICE_KEY = 'email-analyst'
CAPABILITIES = capability_manifest(SERVICE_KEY)

FINDING_FIELDS = [
    "id", "name", "what_found", "raw_evidence_ids", "interpretation",
    "mitre_attack", "confidence", "severity", "score", "threat_intel",
    "first_seen", "last_seen", "related_iocs", "source", "status",
]
