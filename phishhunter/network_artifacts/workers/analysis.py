from __future__ import annotations
from typing import Any
from phishhunter.network_artifacts.orchestrator import analyze_artifacts

def run(artifacts, blobs, callback=None) -> dict[str, Any]:
    return analyze_artifacts(artifacts, blobs, callback)
