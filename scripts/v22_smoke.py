"""End-to-end smoke check for the v22 connected API."""
import os, sys, uuid
os.chdir(os.path.dirname(os.path.dirname(__file__))); sys.path.insert(0, ".")
from fastapi.testclient import TestClient
from phishhunter.main import app

c=TestClient(app)
email=f"v22smoke_{uuid.uuid4().hex[:8]}@example.test"; password="StrongV22Password!2026"; org=f"V22Smoke-{uuid.uuid4().hex[:8]}"
r=c.get('/register'); csrf=c.cookies.get('phishhunter_csrf'); assert r.status_code==200
assert c.post('/register',data={'email':email,'password':password,'organization':org,'csrf_token':csrf},follow_redirects=False).status_code==303
c.get('/login'); csrf=c.cookies.get('phishhunter_csrf'); assert c.post('/login',data={'email':email,'password':password,'csrf_token':csrf},follow_redirects=False).status_code==303
h={'X-CSRF-Token':c.cookies.get('phishhunter_csrf')}
assert c.get('/api/v1/auth/me').status_code==200
assert c.get('/api/v1/dashboard/summary').status_code==200
assert c.post('/api/v1/cases',json={'title':'Smoke Case','priority':'medium','notes':'v22'},headers=h).status_code==200
r=c.post('/api/v1/artifacts',files={'files':('smoke.log',b'10.0.0.1 8.8.8.8 DNS example.test\n','text/plain')},headers=h); assert r.status_code==200,r.text
job=r.json()['job_id']; assert c.post(f'/api/v1/jobs/{job}/start',headers=h).status_code==200
row=c.get(f'/api/v1/jobs/{job}').json(); assert row['status']=='completed',row
assert c.get('/api/v1/iocs').status_code==200
assert c.get('/api/v1/reports').status_code==200
assert c.get('/api/v1/artifacts').status_code==200
print('V22_CONNECTED_BACKEND_SMOKE_PASS')
