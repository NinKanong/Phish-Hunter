"""Worker facade for Sandbox."""
from phishhunter.tasks.sandbox_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
