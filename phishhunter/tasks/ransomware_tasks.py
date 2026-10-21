"""Task entry points for Ransomware; safe to run synchronously or from a worker queue."""
from phishhunter.services.ransomware import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
