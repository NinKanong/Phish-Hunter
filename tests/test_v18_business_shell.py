from __future__ import annotations
import re
import secrets
from fastapi.testclient import TestClient
from phishhunter.main import app

def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert m
    return m.group(1)

def test_login_returns_to_normal_home_and_profile_menu_is_present():
    email = f"v18-{secrets.token_hex(5)}@example.test"
    with TestClient(app) as client:
        reg = client.get('/register')
        r = client.post('/register', data={
            'email': email,
            'password': 'StrongPassword-12345!',
            'organization': f'V18 {secrets.token_hex(3)}',
            'confirm_password': 'StrongPassword-12345!',
            'agree_terms': 'on',
            'csrf_token': _csrf(reg.text),
        }, follow_redirects=False)
        assert r.status_code == 303
        login = client.get('/login')
        r = client.post('/login', data={'email': email, 'password':'StrongPassword-12345!', 'csrf_token':_csrf(login.text)}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers['location'] == '/'
        home = client.get('/')
        assert home.status_code == 200
        assert 'Home' in home.text
        assert 'Dashboard' in home.text
        assert 'data-account-toggle' in home.text
        assert 'Manage account' in home.text
        assert 'data-blacklight-toggle' not in home.text
        assert 'k4-floating-blacklight' not in home.text
        assert 'data-theme="dark"' in home.text
        dashboard = client.get('/dashboard')
        assert dashboard.status_code == 200
        team = client.get('/team')
        assert team.status_code == 200
