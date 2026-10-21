from __future__ import annotations

import re
import secrets

from fastapi.testclient import TestClient

from admin_app import app as admin_app
from phishhunter.db.database import SessionLocal
from phishhunter.main import app as web_app
from phishhunter.models import Tenant, User, UserActivity, UserControl
from phishhunter.security.passwords import hash_password


def csrf(html: str) -> str:
    m = re.search(r'name="csrf"[^>]*value="([^"]+)', html)
    assert m
    return m.group(1)


def test_admin_can_create_roles_disable_reset_delete_and_user_detail():
    suffix = secrets.token_hex(4)
    admin_email = f"root-{suffix}@example.test"
    analyst_email = f"analyst-{suffix}@example.test"
    managed_email = f"managed-{suffix}@example.test"
    admin_password = "Admin-Password-12345!"
    analyst_password = "Analyst-Password-12345!"
    reset_password = "Reset-Password-12345!"
    with SessionLocal() as db:
        tenant = Tenant(name=f"Identity Test {suffix}")
        db.add(tenant); db.flush()
        admin = User(tenant_id=tenant.id, email=admin_email, password_hash=hash_password(admin_password), is_admin=True)
        db.add(admin); db.flush()
        db.commit()
        tenant_id, admin_id = tenant.id, admin.id
    try:
        with TestClient(web_app) as web:
            page = web.get('/register')
            reg = web.post('/register', data={
                'email': analyst_email, 'password': analyst_password, 'confirm_password': analyst_password,
                'organization': f"Identity Test {suffix}", 'agree_terms': 'on', 'csrf_token': re.search(r'name="csrf_token"[^>]*value="([^"]+)', page.text).group(1),
            }, follow_redirects=False)
            assert reg.status_code == 303
            page = web.get('/login')
            login = web.post('/login', data={'email': analyst_email, 'password': analyst_password, 'csrf_token': re.search(r'name="csrf_token"[^>]*value="([^"]+)', page.text).group(1)}, follow_redirects=False)
            assert login.status_code == 303

        with TestClient(admin_app) as admin_client:
            page = admin_client.get('/login')
            login = admin_client.post('/login', data={'email': admin_email, 'password': admin_password, 'csrf': csrf(page.text)}, follow_redirects=False)
            assert login.status_code == 303

            users_page = admin_client.get('/?view=users')
            create = admin_client.post('/users/create', data={
                'email': managed_email, 'password': analyst_password, 'tenant_id': tenant_id,
                'display_name': 'Managed Analyst', 'job_title': 'Security Analyst', 'role': 'analyst', 'csrf': csrf(users_page.text)
            }, follow_redirects=False)
            assert create.status_code == 303

            with SessionLocal() as db:
                managed = db.query(User).filter_by(email=managed_email).one()
                managed_id = managed.id
                assert managed.is_admin is False

            detail = admin_client.get(f'/users/{managed_id}')
            assert detail.status_code == 200
            assert 'Login frequency &amp; activity' in detail.text
            assert 'Account activity history' in detail.text

            role = admin_client.post(f'/users/{managed_id}/role', data={'role': 'admin', 'csrf': csrf(detail.text)}, follow_redirects=False)
            assert role.status_code == 303
            disable = admin_client.post(f'/users/{managed_id}/toggle', data={'csrf': csrf(admin_client.get(f'/users/{managed_id}').text)}, follow_redirects=False)
            assert disable.status_code == 303
            with SessionLocal() as db:
                managed = db.get(User, managed_id)
                control = db.query(UserControl).filter_by(user_id=managed_id).one()
                assert managed.is_admin is True
                assert control.disabled is True

            reset = admin_client.post(f'/users/{managed_id}/password', data={'new_password': reset_password, 'confirm_password': reset_password, 'csrf': csrf(admin_client.get(f'/users/{managed_id}').text)}, follow_redirects=False)
            assert reset.status_code == 303
            with SessionLocal() as db:
                managed = db.get(User, managed_id)
                assert managed.password_hash != reset_password
                control = db.query(UserControl).filter_by(user_id=managed_id).one()
                assert control.disabled is False

            enable = admin_client.post(f'/users/{managed_id}/toggle', data={'csrf': csrf(admin_client.get(f'/users/{managed_id}').text)}, follow_redirects=False)
            assert enable.status_code == 303
            role_back = admin_client.post(f'/users/{managed_id}/role', data={'role': 'analyst', 'csrf': csrf(admin_client.get(f'/users/{managed_id}').text)}, follow_redirects=False)
            assert role_back.status_code == 303
            delete = admin_client.post(f'/users/{managed_id}/delete', data={'csrf': csrf(admin_client.get('/?view=users').text)}, follow_redirects=False)
            assert delete.status_code == 303

        with SessionLocal() as db:
            created = db.query(User).filter_by(email=analyst_email).one()
            assert created.is_admin is False
            assert db.query(UserActivity).filter_by(user_id=created.id, action='account.created').count() == 1
            assert db.query(User).filter_by(email=managed_email).first() is None
    finally:
        with SessionLocal() as db:
            ids = [u.id for u in db.query(User).filter(User.email.like(f'%{suffix}@example.test')).all()]
            for uid in ids:
                db.query(UserActivity).filter((UserActivity.user_id==uid)|(UserActivity.actor_user_id==uid)).delete(synchronize_session=False)
                db.query(User).filter_by(id=uid).delete(synchronize_session=False)
            tenant = db.get(Tenant, tenant_id)
            if tenant and not db.query(User).filter_by(tenant_id=tenant_id).count():
                db.delete(tenant)
            db.commit()

