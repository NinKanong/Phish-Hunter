"""Worker facade for Email."""
from phishhunter.tasks.email_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
