"""Worker facade for Ioc."""
from phishhunter.tasks.ioc_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
