"""Task entry points for Actors; safe to run synchronously or from a worker queue."""
from phishhunter.services.actors import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
