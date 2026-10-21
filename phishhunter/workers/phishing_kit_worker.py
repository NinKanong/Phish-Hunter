"""Worker facade for PhishingKit."""
from phishhunter.tasks.phishing_kit_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
