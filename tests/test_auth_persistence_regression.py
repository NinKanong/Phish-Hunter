from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from phishhunter.main import app
from phishhunter.db.database import PROJECT_ROOT, SessionLocal
from phishhunter.models import Tenant, User, UserControl, UserProfile
from phishhunter.security.passwords import hash_password


def _csrf(html: str, name: str = "csrf_token") -> str:
    match = re.search(rf'name="{name}"[^>]*value="([^"]+)"', html)
    assert match, f"CSRF token {name!r} not found"
    return match.group(1)


def test_relative_sqlite_database_is_stable_across_working_directories(tmp_path: Path):
    db_rel = f"sqlite:///./data/auth-path-regression-{os.getpid()}.db"
    db_path = PROJECT_ROOT / "data" / f"auth-path-regression-{os.getpid()}.db"
    if db_path.exists():
        db_path.unlink()

    env = os.environ.copy()
    env["DATABASE_URL"] = db_rel
    env["PYTHONPATH"] = str(PROJECT_ROOT)

    writer = """
from phishhunter.db.database import SessionLocal
from phishhunter.models import Tenant, User, UserProfile, UserControl
from phishhunter.security.passwords import hash_password
with SessionLocal() as db:
    tenant = Tenant(name='stable-path-tenant')
    db.add(tenant); db.flush()
    user = User(tenant_id=tenant.id, email='stable-path@example.test', password_hash=hash_password('Stable-Password-12345!'))
    db.add(user); db.flush()
    db.add(UserProfile(user_id=user.id, display_name='Stable Path'))
    db.add(UserControl(user_id=user.id))
    db.commit()
    print(user.id)
"""
    reader = """
from phishhunter.db.database import SessionLocal
from phishhunter.models import User
with SessionLocal() as db:
    user = db.query(User).filter_by(email='stable-path@example.test').first()
    assert user is not None
    print(user.email)
"""
    try:
        first = subprocess.run([sys.executable, "-c", writer], cwd=PROJECT_ROOT, env=env, text=True, capture_output=True, check=True)
        second = subprocess.run([sys.executable, "-c", reader], cwd=tmp_path, env=env, text=True, capture_output=True, check=True)
        assert "stable-path@example.test" in second.stdout
        assert db_path.exists()
    finally:
        if db_path.exists():
            db_path.unlink()


def test_admin_created_account_can_login_again_from_main_site():
    admin_email = "regression-admin@example.test"
    analyst_email = "created-by-admin@example.test"
    password = "Admin-Created-Password-12345!"
    with SessionLocal() as db:
        existing = db.query(User).filter(User.email.in_([admin_email, analyst_email])).all()
        for user in existing:
            db.query(UserControl).filter_by(user_id=user.id).delete(synchronize_session=False)
            db.query(UserProfile).filter_by(user_id=user.id).delete(synchronize_session=False)
            db.delete(user)
        db.commit()
        tenant = Tenant(name="Regression Admin Tenant")
        db.add(tenant); db.flush()
        admin = User(tenant_id=tenant.id, email=admin_email, password_hash=hash_password(password), is_admin=True)
        db.add(admin); db.flush()
        db.add(UserProfile(user_id=admin.id, display_name="Regression Admin", job_title="Administrator"))
        db.add(UserControl(user_id=admin.id))
        db.commit()
        admin_id = admin.id
        tenant_id = tenant.id

    try:
        with TestClient(app) as admin_client:
            login_page = admin_client.get("/admin/login")
            assert login_page.status_code == 200
            login = admin_client.post(
                "/admin/login",
                data={"email": admin_email, "password": password, "csrf": _csrf(login_page.text, "csrf")},
                follow_redirects=False,
            )
            assert login.status_code == 303

            create = admin_client.post(
                "/admin/users/create",
                data={
                    "email": analyst_email,
                    "password": password,
                    "tenant_id": tenant_id,
                    "display_name": "Created Analyst",
                    "csrf": _csrf(admin_client.get("/admin/?view=users").text, "csrf"),
                },
                follow_redirects=False,
            )
            assert create.status_code == 303

        with SessionLocal() as db:
            user = db.query(User).filter_by(email=analyst_email).first()
            assert user is not None
            assert user.is_admin is False
            assert user.password_hash != password
            assert user.tenant_id == tenant_id

        with TestClient(app) as client:
            login_page = client.get("/login")
            response = client.post(
                "/login",
                data={"email": analyst_email, "password": password, "csrf_token": _csrf(login_page.text)},
                follow_redirects=False,
            )
            assert response.status_code == 303
            assert response.headers["location"] == "/"
            assert "access_token" in client.cookies
    finally:
        with SessionLocal() as db:
            user = db.query(User).filter_by(email=analyst_email).first()
            admin = db.get(User, admin_id)
            for target in [user, admin]:
                if target:
                    db.query(UserControl).filter_by(user_id=target.id).delete(synchronize_session=False)
                    db.query(UserProfile).filter_by(user_id=target.id).delete(synchronize_session=False)
                    db.delete(target)
            tenant = db.get(Tenant, tenant_id)
            if tenant:
                db.delete(tenant)
            db.commit()
