from __future__ import annotations

import re
import secrets

from fastapi.testclient import TestClient

from phishhunter.main import app


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match
    return match.group(1)


def test_authenticated_user_persists_across_isolated_services():
    email = f"k4-{secrets.token_hex(5)}@example.test"
    with TestClient(app) as client:
        page = client.get("/register")
        response = client.post(
            "/register",
            data={
                "email": email,
                "password": "StrongPassword-12345!",
                "organization": f"K4 Test Tenant {secrets.token_hex(4)}",
                "confirm_password": "StrongPassword-12345!",
                "agree_terms": "on",
                "csrf_token": _csrf(page.text),
            },
            follow_redirects=False,
        )
        assert response.status_code == 303

        page = client.get("/login")
        response = client.post(
            "/login",
            data={"email": email, "password": "StrongPassword-12345!", "csrf_token": _csrf(page.text)},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "access_token" in client.cookies

        first = client.get("/services/pcap-analyst")
        second = client.get("/services/file-analyst")
        assert email in first.text
        assert email in second.text

        result = client.post("/services/graph", data={"indicator": "example.com 203.0.113.8"})
        assert result.status_code == 200
        assert "ACCOUNT SAVED" in result.text
        assert email in result.text
