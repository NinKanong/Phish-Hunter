"""Task entry points for Ioc; safe to run synchronously or from a worker queue."""
from phishhunter.services.ioc import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
