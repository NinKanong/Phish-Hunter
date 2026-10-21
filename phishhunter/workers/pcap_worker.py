"""Worker facade for Pcap."""
from phishhunter.tasks.pcap_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
