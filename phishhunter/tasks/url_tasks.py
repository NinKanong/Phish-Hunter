"""Task entry points for Url; safe to run synchronously or from a worker queue."""
from phishhunter.services.url import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
