import asyncio
import inspect

from phishhunter.analyzers.unified_url_domain import _bounded, analyze_url_domain
from phishhunter.url_domain_analyst import engine


def test_analyzer_accepts_profile_argument():
    assert "profile" in inspect.signature(analyze_url_domain).parameters


def test_bounded_collector_timeout_is_structured():
    async def slow():
        await asyncio.sleep(0.7)
        return {"status": "completed"}
    result = asyncio.run(_bounded("test", slow(), 0.5))
    assert result["status"] == "timeout"
    assert result["provider"] == "test"


def test_engine_analyze_is_async():
    assert inspect.iscoroutinefunction(engine.analyze)


def test_result_navigation_has_no_js_fallback_and_isolated_targets(monkeypatch):
    from fastapi.testclient import TestClient
    from phishhunter.main import app
    import phishhunter.web.services as services
    result = {
        "target":"example.com","domain":"example.com","target_type":"domain","registered_domain":"example.com",
        "risk_score":5,"verdict":"low-risk","iocs":{},"evidence":[],"timeline":[],
        "whois_rdap":{},"dns":{},"certificate_transparency":{},"http":{},"graph":{"nodes":[],"edges":[]},
        "url_domain_vnext":{},
    }
    monkeypatch.setattr(services, "analyze_url_domain", lambda target, profile="deep": dict(result))
    r=TestClient(app).post("/services/url-domain-analyst",data={"target":"example.com","profile":"quick","authorized":"1"})
    assert r.status_code == 200
    assert 'href="#uha-dns"' in r.text
    assert 'id="uha-dns"' in r.text
    assert '.uha-section:first-of-type{display:block}' in r.text
    assert ':target{display:block}' in r.text
    assert 'id="uhaCurrentModule"' in r.text
