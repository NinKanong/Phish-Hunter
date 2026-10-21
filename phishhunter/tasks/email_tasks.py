"""Task entry points for Email; safe to run synchronously or from a worker queue."""
from phishhunter.services.email import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
