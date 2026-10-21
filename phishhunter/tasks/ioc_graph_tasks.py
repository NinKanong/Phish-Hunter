"""Task entry points for IocGraph; safe to run synchronously or from a worker queue."""
from phishhunter.services.ioc_graph import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
