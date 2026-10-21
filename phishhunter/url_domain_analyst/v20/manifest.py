from __future__ import annotations
from pathlib import Path

VERSION = "20.0.0"
CANONICAL_RUNTIME = "phishhunter/url_domain_analyst"
SOURCE_MIRROR = "phishhunter/url & domain analyst"


def runtime_counts(root: str | Path) -> dict[str, int]:
    path = Path(root)
    return {
        "python_files": sum(1 for p in path.rglob("*.py") if p.is_file()),
        "all_files": sum(1 for p in path.rglob("*") if p.is_file()),
    }
