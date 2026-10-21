"""Worker facade for IocGraph."""
from phishhunter.tasks.ioc_graph_tasks import run

def execute(payload: dict, target: str = "") -> dict:
    return run(payload, target)
