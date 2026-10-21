from __future__ import annotations

STAGES = (
    "intake", "normalization", "url_anatomy", "domain_anatomy", "dns", "rdap",
    "certificate_transparency", "http", "tls", "infrastructure", "reputation",
    "breach", "detections", "graph", "risk", "evidence", "geography",
    "services_banners", "attack_surface", "dns_temporal", "certificate_reuse",
    "asn", "cloud", "osint", "exposure_matrix", "risk_calibration",
    "chain_summary", "watch_plan", "deep_reasoning", "ai_task_plan", "complete",
)

def stage_count() -> int:
    return len(STAGES)
