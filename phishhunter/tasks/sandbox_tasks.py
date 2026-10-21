"""Task entry points for Sandbox; safe to run synchronously or from a worker queue."""
from phishhunter.services.sandbox import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
