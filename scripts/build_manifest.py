from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", ".git"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".db", ".sample"}


def main() -> int:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        files.append(rel.as_posix())
    files.sort()
    manifest = {
        "project": "cyber-phish-k4",
        "version": "23.0.0",
        "generated_at": "2026-10-01T00:00:00Z",
        "total_files": len(files),
        "files": files,
    }
    (ROOT / "FILE_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"MANIFEST_WRITTEN {len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
