"""Task entry points for Domain; safe to run synchronously or from a worker queue."""
from phishhunter.services.domain import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
