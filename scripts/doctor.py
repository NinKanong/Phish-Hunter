from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
COMMON = ROOT / "libs" / "py-common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))


def usage() -> None:
    print("Usage: python scripts/doctor.py")


def check(name: str, fn) -> tuple[str, bool, str]:
    try:
        result = fn()
        detail = "PASS" if result in (None, True) else str(result)
        return name, True, detail
    except Exception as exc:
        return name, False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    from phishhunter.analyzers.file_analyzer import analyze_file
    from phishhunter.analyzers.email_analyzer import analyze_email
    from phishhunter.analysis.graph_builder import build_graph
    from phishhunter.security.url_guard import validate_url

    checks = [
        ("FastAPI import", lambda: importlib.import_module("fastapi")),
        ("SQLAlchemy import", lambda: importlib.import_module("sqlalchemy")),
        ("Static file engine", lambda: analyze_file("sample.bin", b"PowerShell Invoke-WebRequest https://example.test/x")),
        ("Email parser", lambda: analyze_email(b"From: test@example.test\r\nSubject: Test\r\n\r\nhello")),
        ("Graph builder", lambda: build_graph({"url": "https://example.test", "iocs": {"domains": ["example.test"]}, "mitre_techniques": []})),
        ("SSRF guard", lambda: blocked_check(validate_url)),
    ]
    failed = 0
    for name, fn in checks:
        title, ok, detail = check(name, fn)
        print(f"[{ 'PASS' if ok else 'FAIL' }] {title}: {detail}")
        failed += int(not ok)
    print(json.dumps({"doctor": "PASS" if failed == 0 else "FAIL", "failed_checks": failed}, indent=2))
    return 0 if failed == 0 else 1


def blocked_check(validate):
    try:
        validate("http://127.0.0.1/")
    except ValueError:
        return True
    raise AssertionError("SSRF guard accepted loopback")


if __name__ == "__main__":
    raise SystemExit(main())
