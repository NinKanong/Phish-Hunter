"""Task entry points for File; safe to run synchronously or from a worker queue."""
from phishhunter.services.file import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
