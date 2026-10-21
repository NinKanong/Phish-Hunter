"""Task entry points for Campaigns; safe to run synchronously or from a worker queue."""
from phishhunter.services.campaigns import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
