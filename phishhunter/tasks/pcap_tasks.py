"""Task entry points for Pcap; safe to run synchronously or from a worker queue."""
from phishhunter.services.pcap import normalize

def run(result: dict, target: str = "") -> dict:
    return normalize(result, target)
