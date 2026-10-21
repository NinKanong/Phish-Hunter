"""Task entry points for Feeds; safe to run synchronously or from a worker queue."""
from phishhunter.services.feeds import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
