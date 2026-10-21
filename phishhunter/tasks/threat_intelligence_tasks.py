"""Task entry points for ThreatIntelligence; safe to run synchronously or from a worker queue."""
from phishhunter.services.threat_intelligence import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
