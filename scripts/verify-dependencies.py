from __future__ import annotations

import argparse
import importlib.metadata as metadata
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_REQUIREMENTS = ROOT / "requirements" / "base.txt"


EXPECTED_IMPORT_DISTS = {
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "jinja2": "jinja2",
    "python-multipart": "multipart",
    "pydantic": "pydantic",
    "pydantic-settings": "pydantic_settings",
    "SQLAlchemy": "sqlalchemy",
    "argon2-cffi": "argon2",
    "PyJWT": "jwt",
    "httpx": "httpx",
    "beautifulsoup4": "bs4",
}


def usage() -> None:
    print("Usage: python scripts/verify-dependencies.py [--strict]")


def declared_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in BASE_REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][^\s#]*)", line)
        if match:
            pins[match.group(1).lower().replace("_", "-")] = match.group(2)
    return pins


def normalized_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify installed PhishGuard dependencies.")
    parser.add_argument("--strict", action="store_true", help="require exact versions from requirements/base.txt")
    args = parser.parse_args()

    print(f"Python: {sys.version.split()[0]}")
    pins = declared_pins()
    failed = []

    for dist_name, import_name in EXPECTED_IMPORT_DISTS.items():
        installed = normalized_version(dist_name)
        expected = pins.get(dist_name.lower().replace("_", "-"))
        if installed is None:
            failed.append(f"{dist_name}: not installed")
            print(f"[FAIL] {dist_name}: not installed")
            continue
        if args.strict and expected and installed != expected:
            failed.append(f"{dist_name}: expected {expected}, found {installed}")
            print(f"[FAIL] {dist_name}: expected {expected}, found {installed}")
            continue
        suffix = f" (declared {expected})" if expected else ""
        print(f"[PASS] {dist_name} {installed}{suffix}")

    try:
        import pydantic
        import pydantic_core
        print(f"[PASS] pydantic runtime {pydantic.__version__}")
        print(f"[PASS] pydantic-core runtime {pydantic_core.__version__}")
        core_requirement = [
            item for item in (metadata.requires("pydantic") or [])
            if "pydantic-core" in item.lower()
        ]
        if core_requirement:
            print("Pydantic core requirement:", ", ".join(core_requirement))
        if args.strict and pins.get("pydantic-core") != pydantic_core.__version__:
            failed.append(
                f"pydantic-core: expected {pins.get('pydantic-core')}, found {pydantic_core.__version__}"
            )
            print(
                f"[FAIL] pydantic-core exact pin: expected {pins.get('pydantic-core')}, "
                f"found {pydantic_core.__version__}"
            )
    except Exception as exc:
        failed.append(f"pydantic runtime: {exc}")
        print(f"[FAIL] pydantic runtime: {exc}")

    if failed:
        print("Dependency verification FAILED")
        for item in failed:
            print(f"  - {item}")
        return 1
    print("Dependency verification PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
