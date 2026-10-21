"""Task entry points for Ip; safe to run synchronously or from a worker queue."""
from phishhunter.services.ip import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
