"""Worker facade for Domain."""
from phishhunter.tasks.domain_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
