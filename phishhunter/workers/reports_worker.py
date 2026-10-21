"""Worker facade for Reports."""
from phishhunter.tasks.reports_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
