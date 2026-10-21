"""Worker facade for Campaigns."""
from phishhunter.tasks.campaigns_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
