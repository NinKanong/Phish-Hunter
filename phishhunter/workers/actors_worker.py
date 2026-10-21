"""Worker facade for Actors."""
from phishhunter.tasks.actors_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
