"""Worker facade for Ip."""
from phishhunter.tasks.ip_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
