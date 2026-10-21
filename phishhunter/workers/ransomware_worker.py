"""Worker facade for Ransomware."""
from phishhunter.tasks.ransomware_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
