from __future__ import annotations

from importlib import import_module
import os
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
COMMON = ROOT / "libs" / "py-common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

REQUIRED_IMPORTS = [
    "fastapi",
    "uvicorn",
    "jinja2",
    "multipart",
    "pydantic",
    "pydantic_settings",
    "sqlalchemy",
    "argon2",
    "jwt",
    "httpx",
    "bs4",
    "phishhunter",
    "phishhunter.main",
    "phishhunter.analyzers.file_analyzer",
    "phishhunter.analyzers.email_analyzer",
    "phishhunter.analyzers.url_analyzer",
    "phishhunter_common.hash",
    "phishhunter_common.ioc",
]


def usage() -> None:
    print("Usage: python scripts/preflight.py")


def main() -> int:
    version = sys.version_info
    print(f"Platform: {platform.platform()}")
    print(f"Python: {platform.python_version()}")
    if (version.major, version.minor) not in {(3, 12), (3, 13), (3, 14)}:
        print("ERROR: PhishGuard v2.5 supports Python 3.12, 3.13, and 3.14.")
        return 2

    failed = []
    for module in REQUIRED_IMPORTS:
        try:
            import_module(module)
        except Exception as exc:  # pragma: no cover - diagnostic path
            failed.append((module, repr(exc)))
    if failed:
        print("Import checks failed:")
        for module, error in failed:
            print(f"  - {module}: {error}")
        print("Install the matching requirements before starting the server.")
        return 3

    if len(os.getenv("SECRET_KEY", "dev-only-change-me-please-32-bytes")) < 32:
        print("ERROR: SECRET_KEY must be at least 32 characters for HS256 signing.")
        return 4

    for path in (Path("data"), Path("data/storage")):
        path.mkdir(parents=True, exist_ok=True)
        if not os.access(path, os.W_OK):
            print(f"ERROR: not writable: {path}")
            return 4

    forbidden = []
    for name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
        if Path(name).exists():
            forbidden.append(name)
    if forbidden:
        print("ERROR: Docker artifacts found in this project:", ", ".join(forbidden))
        return 5

    print("Preflight: PASS")
    print("Database: SQLite default")
    print("Dynamic execution: disabled unless an external isolated sandbox is explicitly configured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
