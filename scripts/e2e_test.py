from __future__ import annotations

import io
import re
import sys
import uuid
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
    print("Usage: python scripts/e2e_test.py")


def csrf_token(client: TestClient) -> str:
    page = client.get("/register")
    match = re.search(r'name="csrf_token" value="([0-9a-f]{64})"', page.text)
    if not match:
        raise AssertionError("CSRF token missing")
    return match.group(1)


def main() -> int:
    email = f"e2e-{uuid.uuid4().hex[:10]}@example.test"
    password = "Test-Password-2026!"
    with TestClient(app) as client:
        token = csrf_token(client)
        response = client.post(
            "/register",
            data={"email": email, "password": password, "organization": f"E2E-{uuid.uuid4().hex[:8]}", "csrf_token": token},
            follow_redirects=False,
        )
        assert response.status_code == 303

        token = csrf_token(client)
        response = client.post(
            "/login", data={"email": email, "password": password, "csrf_token": token}, follow_redirects=False
        )
        assert response.status_code == 303
        assert client.get("/dashboard").status_code == 200
        assert client.get("/api/v1/scans").status_code == 200

        token = csrf_token(client)
        sample = b"PowerShell Invoke-WebRequest URLDownloadToFile CreateRemoteThread https://example.test/payload"
        response = client.post(
            "/analyze/malware",
            data={"csrf_token": token},
            files={"file": ("sample.bin", io.BytesIO(b"MZ" + sample), "application/octet-stream")},
        )
        assert response.status_code == 200
        match = re.search(r"Scan #(\d+)", response.text)
        if not match:
            raise AssertionError("scan id not rendered")
        scan_id = int(match.group(1))
        assert client.get(f"/graph/{scan_id}").status_code == 200
        assert client.get(f"/api/v1/scans/{scan_id}").status_code == 200
        assert client.get(f"/api/v1/scans/{scan_id}/graph").status_code == 200
        assert client.get(f"/reports/{scan_id}/json").status_code == 200

        token = csrf_token(client)
        logout = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
        assert logout.status_code == 303
        assert client.get("/dashboard", follow_redirects=False).status_code == 401

    print("E2E_TEST_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
