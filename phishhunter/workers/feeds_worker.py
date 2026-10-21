"""Worker facade for Feeds."""
from phishhunter.tasks.feeds_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
