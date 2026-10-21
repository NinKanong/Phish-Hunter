from __future__ import annotations

import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
COMMON = ROOT / "libs" / "py-common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
from fastapi.testclient import TestClient

from phishhunter.main import app


def usage() -> None:
    print("Usage: python scripts/smoke_test.py")


def csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([0-9a-f]{64})"', response.text)
    if not match:
        raise AssertionError("CSRF token not found in page")
    return match.group(1)


def main() -> int:
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/metrics").status_code == 200
        register = client.get("/register")
        assert register.status_code == 200
        token = csrf_from(register)
        assert client.post("/login", data={"email": "x@example.invalid", "password": "bad", "csrf_token": "0" * 64}).status_code == 403
        assert client.get("/docs").status_code == 200
        assert client.get("/api/v1/enrichment/catalog").status_code == 200
        # Static analyzers run in-process and do not require a network target for this smoke test.
        assert client.get("/").status_code == 200
    print("SMOKE_TEST_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
