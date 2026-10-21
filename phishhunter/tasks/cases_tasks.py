"""Task entry points for Cases; safe to run synchronously or from a worker queue."""
from phishhunter.services.cases import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
