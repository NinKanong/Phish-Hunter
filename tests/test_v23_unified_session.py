from __future__ import annotations

import re
import secrets

from fastapi.testclient import TestClient

from admin_app import app as admin_app
from phishhunter.db.database import SessionLocal
from phishhunter.main import app as web_app
from phishhunter.models import Tenant, User, UserControl, UserProfile
from phishhunter.security.passwords import hash_password


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf"[^>]*value="([^"]+)"', html)
    assert match
    return match.group(1)


def test_admin_session_is_recognized_by_main_site():
    email = f"v24-admin-{secrets.token_hex(5)}@example.test"
    password = "StrongPassword-12345!"
    with SessionLocal() as db:
        tenant = Tenant(name=f"V24 Session {secrets.token_hex(4)}")
        db.add(tenant)
        db.flush()
        user = User(tenant_id=tenant.id, email=email, password_hash=hash_password(password), is_admin=True)
        db.add(user)
        db.flush()
        profile = db.query(UserProfile).filter_by(user_id=user.id).first()
        if not profile:
            profile = UserProfile(user_id=user.id, display_name="V24 Administrator", job_title="Administrator")
        control = db.query(UserControl).filter_by(user_id=user.id).first()
        if not control:
            control = UserControl(user_id=user.id)
        control.disabled = False
        db.add_all([profile, control])
        db.commit()

    with TestClient(admin_app) as admin:
        login_page = admin.get("/login")
        response = admin.post(
            "/login",
            data={"email": email, "password": password, "csrf": _csrf(login_page.text)},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert admin.cookies.get("k4_admin_access")
        assert admin.cookies.get("access_token")
        assert admin.cookies.get("refresh_token")

        with TestClient(web_app) as web:
            web.cookies.update(admin.cookies)
            home = web.get("/")
            assert home.status_code == 200
            assert email in home.text
            assert "Admin console" in home.text
            assert "Create account" not in home.text
            assert "Sign in" not in home.text

        backend = admin.get("/?view=backend")
        assert backend.status_code == 200
        assert "Backend Architecture" in backend.text
        assert "control plane" in backend.text.lower()
