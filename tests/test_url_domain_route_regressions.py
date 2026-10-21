import io
import json
import zipfile

from fastapi.testclient import TestClient

from phishhunter.main import app
import phishhunter.web.services as services


FAKE_RESULT = {
    "target": "example.com",
    "domain": "example.com",
    "target_type": "domain",
    "registered_domain": "example.com",
    "url": "",
    "verdict": "unknown",
    "risk_score": 12,
    "iocs": {"domains": ["example.com"], "ipv4": [], "urls": [], "emails": []},
    "evidence": [],
    "mitre_techniques": [],
    "ai_analysis": {"mode": "local-evidence-copilot", "status": "ready", "briefing": "ok", "limitations": ""},
    "graph": {"nodes": [], "edges": [], "node_count": 0},
    "certificate_transparency": {"names": []},
    "chain_of_custody": {"package_sha256": "abc"},
    "whois_rdap": {},
    "dns": {},
    "ip_intelligence": {},
    "reputation": {},
    "http": {},
    "timeline": [],
    "breach_intelligence": {"status": "provider-dependent", "records": []},
    "url_forensics": {},
    "domain_overview": {},
    "osint_pivots": [],
    "url_domain_vnext": {},
}


def test_url_domain_post_renders_even_with_sparse_result(monkeypatch):
    monkeypatch.setattr(services, "analyze_url_domain", lambda target: dict(FAKE_RESULT))
    response = TestClient(app).post(
        "/services/url-domain-analyst",
        data={"target": "example.com", "deep_mode": "on", "authorized": "on"},
    )
    assert response.status_code == 200
    assert "URL &amp; Domain Analyst" in response.text
    assert "Undefined is not JSON serializable" not in response.text
    assert "str&#39; object has no attribute &#39;get&#39;" not in response.text


def test_isolated_api_accepts_sync_analyzer(monkeypatch):
    monkeypatch.setattr(services, "analyze_url_domain", lambda target: dict(FAKE_RESULT))
    response = TestClient(app).get("/services/url-domain-analyst/api/geo?target=example.com")
    assert response.status_code == 200
    assert response.json()["section"] == "geo"


def test_workforce_export_is_valid_xlsx():
    rows = json.dumps([{"name": "Alice", "title": "Analyst", "source": "provider", "confidence": 0.9}])
    response = TestClient(app).post(
        "/services/url-domain-analyst/export/workforce.xlsx",
        data={"domain": "example.com", "rows_json": rows},
    )
    assert response.status_code == 200
    assert response.content[:2] == b"PK"
    assert zipfile.is_zipfile(io.BytesIO(response.content))


def test_attack_surface_api_builds_from_dnsdumpster_when_vnext_is_missing(monkeypatch):
    result = dict(FAKE_RESULT)
    result["dnsdumpster"] = {
        "status": "completed",
        "source": "DNSDumpster",
        "records": {
            "a": [{"host": "www.example.com", "ips": [{"ip": "203.0.113.10", "asn": "64500", "asn_name": "ExampleNet", "country": "United States", "country_code": "US", "banners": {"http": {"apps": ["nginx"]}}}]}],
            "cname": [], "mx": [], "ns": [], "txt": [],
        },
    }
    monkeypatch.setattr(services, "analyze_url_domain", lambda target: result)
    response = TestClient(app).get("/services/url-domain-analyst/api/attack-surface?target=example.com&service=nginx")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["pagination"]["total"] == 1
    assert data["a_records_page"][0]["host"] == "www.example.com"


def test_services_banner_export_is_csv():
    rows = json.dumps([{
        "host":"www.example.com","ip":"203.0.113.10","protocol":"https","port":443,
        "service":"nginx","product":"nginx","version":"1.25","server":"nginx",
        "title":"ok","source":"DNSDumpster"
    }])
    response = TestClient(app).post(
        "/services/url-domain-analyst/export/services.csv",
        data={"domain":"example.com","rows_json":rows},
    )
    assert response.status_code == 200
    assert "host,ip,protocol,port" in response.text
    assert "www.example.com" in response.text
