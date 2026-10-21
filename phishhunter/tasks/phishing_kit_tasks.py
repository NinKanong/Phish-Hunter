"""Task entry points for PhishingKit; safe to run synchronously or from a worker queue."""
from phishhunter.services.phishing_kit import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
