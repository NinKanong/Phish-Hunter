"""Evidence rules for Ioc.

Rules are intentionally declarative: they never claim external intelligence that
has not been returned by a configured connector.
"""

RULES = [
    {"id": "IOC-EVIDENCE-001", "name": "raw-evidence-required", "description": "Every analyst finding must link to raw evidence."},
    {"id": "IOC-CONF-001", "name": "confidence-required", "description": "Every finding carries a numeric 0-100 confidence value."},
    {"id": "IOC-TIMELINE-001", "name": "timeline-required", "description": "Every retained observation receives an observation timestamp."},
    {"id": "IOC-INTEL-001", "name": "intel-status-explicit", "description": "Every IOC has an explicit provider status; unavailable providers are never represented as successful lookups."},
]
