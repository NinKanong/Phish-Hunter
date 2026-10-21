"""Worker facade for Cases."""
from phishhunter.tasks.cases_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
