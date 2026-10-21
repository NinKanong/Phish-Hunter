from pathlib import Path

from fastapi.testclient import TestClient

from phishhunter.main import app
from phishhunter.db.database import Base, engine, SessionLocal
from phishhunter.models import Tenant, User, UserProfile, UserControl
from phishhunter.security.passwords import hash_password
from phishhunter.security.jwt import create_access_token


def _seed_admin():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="Continuity Test")
            db.add(tenant)
            db.flush()
        user = db.query(User).filter_by(email="continuity-admin@example.com").first()
        if not user:
            user = User(tenant_id=tenant.id, email="continuity-admin@example.com", password_hash=hash_password("continuity-password-123"), is_admin=True)
            db.add(user)
            db.flush()
        else:
            user.is_admin = True
            user.password_hash = hash_password("continuity-password-123")
        profile = db.query(UserProfile).filter_by(user_id=user.id).first()
        if not profile:
            profile = UserProfile(user_id=user.id, display_name="Continuity Admin", job_title="Administrator")
        control = db.query(UserControl).filter_by(user_id=user.id).first()
        if not control:
            control = UserControl(user_id=user.id)
        control.disabled = False
        db.add_all([profile, control])
        db.commit()
        return user.id


def test_public_pages_keep_authenticated_navigation():
    uid = _seed_admin()
    token = create_access_token(str(uid))
    client = TestClient(app)
    client.cookies.set("access_token", token)
    for path in ["/blog", "/about", "/docs", "/status", "/support", "/contact"]:
        response = client.get(path)
        assert response.status_code == 200
        body = response.text
        assert "Admin Control" in body
        assert 'href="/login"' not in body
        assert 'href="/register"' not in body
        assert "SYSTEM ONLINE" not in body
        assert "v18.0" not in body


def test_header_does_not_show_removed_account_items_or_search_button():
    uid = _seed_admin()
    token = create_access_token(str(uid))
    client = TestClient(app)
    client.cookies.set("access_token", token)
    body = client.get("/about").text
    assert 'title="Search"' not in body
    assert ">Team <" not in body
    assert "Billing &amp; plan" not in body
    assert "API keys &amp; API docs" not in body
