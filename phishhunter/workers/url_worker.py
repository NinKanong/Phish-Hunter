"""Worker facade for Url."""
from phishhunter.tasks.url_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
