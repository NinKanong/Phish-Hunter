import asyncio

from phishhunter.url_domain_analyst.api import capabilities, capability_catalog
from phishhunter.url_domain_analyst.url.anatomy import analyze as analyze_url
from phishhunter.url_domain_analyst.domain.anatomy import analyze as analyze_domain
from phishhunter.url_domain_analyst.graph import relationship_contract, build_graph
from phishhunter.url_domain_analyst.orchestration.pipeline import plan


def test_capability_registry_is_deep_and_bigger_than_blueprint_minimum():
    c = capabilities()
    assert c['internal_capability_count'] >= 400
    assert len(capability_catalog()) == c['internal_capability_count']
    assert len(c['layers']) == 12


def test_url_anatomy_exposes_contract_and_obfuscation():
    r = analyze_url('https://user:pass@example.com/%252e%252e/login?token=YWJjZGVmZ2hpams=')
    assert r['authority']['userinfo_present'] is True
    assert r['obfuscation']['score'] > 0
    assert len(r['field_contract']) >= 180
    assert r['hashes']['sha256']


def test_domain_anatomy_handles_multi_label_suffix_and_idn_signals():
    r = analyze_domain('login.example.co.uk')
    assert r['registered_domain'] == 'example.co.uk'
    assert r['subdomain_depth'] == 1
    assert 'field_map_version' in r['field_contract']


def test_graph_contract_has_movable_isolation_features():
    c = relationship_contract()
    assert c['interaction']['drag']
    assert c['interaction']['pan']
    assert c['interaction']['click_to_isolate']
    graph = build_graph({'target':'example.com','domain':'example.com','url':'https://example.com/','dns':{'records':{'A':[{'value':'93.184.216.34'}]}},'certificate_transparency':{},'http':{},'technology':[]})
    assert graph['node_count'] >= 2
    assert graph['edge_count'] >= 1


def test_pipeline_is_explicit_and_modular():
    stages = plan()
    assert len(stages) >= 20
    assert stages[0]['stage'] == 'normalize'
    assert stages[-1]['stage'] == 'reporting'

def test_web_route_is_wired_to_module_engine():
    import phishhunter.web.services as services
    assert services.analyze_url_domain.__module__ == 'phishhunter.url_domain_analyst.engine'
