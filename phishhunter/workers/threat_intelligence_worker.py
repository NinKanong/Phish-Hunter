"""Worker facade for ThreatIntelligence."""
from phishhunter.tasks.threat_intelligence_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
