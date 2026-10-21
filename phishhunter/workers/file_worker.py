"""Worker facade for File."""
from phishhunter.tasks.file_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
