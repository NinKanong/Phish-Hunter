from phishhunter.url_domain_analyst.recon.tool_catalog import TOOL_CATALOG, stats
from phishhunter.url_domain_analyst.recon.domain_health import build as build_health
from phishhunter.url_domain_analyst.recon.registrant_intelligence import build as build_registrant
from phishhunter.url_domain_analyst.recon.investigation_plan import build as build_plan


def test_named_tool_catalog_is_realistic_and_over_100():
    assert len(TOOL_CATALOG) >= 140
    names={x['name'] for x in TOOL_CATALOG}
    for n in ('Amass','Subfinder','MassDNS','PureDNS','httpx','Nmap','Neo4j','BloodHound CE','SpiderFoot','Censys'):
        assert n in names
    assert stats()['gated_active'] > 0


def test_domain_health_always_has_28_checks_and_explicit_unavailable_state():
    out=build_health({'domain':'example.com'})
    assert len(out['checks']) == 28
    assert out['summary']['unavailable'] == 28
    assert out['policy']['no_fabricated_counts'] is True


def test_registrant_intelligence_has_deep_contract_without_inference():
    out=build_registrant({'domain':'example.com','registrant':{}}, {})
    assert len(out['fields']) >= 60
    assert out['summary']['identity_state'] == 'not-observed'
    assert 'private-person identity' in out['evidence_boundary']


def test_recon_plan_gates_active_and_internal_modules():
    out=build_plan('example.com')
    assert len(out['modules']) == 7
    assert all(m['status'] == 'gated' for m in out['modules'] if m['mode'] in {'authorized-active','authorized-internal'})
    out2=build_plan('example.com', explicit_scope=True, internal_scope=True)
    assert any(m['status']=='ready' for m in out2['modules'] if m['mode']=='authorized-active')
    assert any(m['status']=='ready' for m in out2['modules'] if m['mode']=='authorized-internal')
