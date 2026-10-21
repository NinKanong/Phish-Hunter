"""Task entry points for Reports; safe to run synchronously or from a worker queue."""
from phishhunter.services.reports import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
