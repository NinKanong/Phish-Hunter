
from phishhunter.url_domain_analyst.geo.location_intel import build as build_geo
from phishhunter.url_domain_analyst.services.banners import build as build_banners
from phishhunter.url_domain_analyst.orchestration.stage_registry import plan
from phishhunter.url_domain_analyst.url.similarity import similarity
from phishhunter.url_domain_analyst.domain.typosquat import candidates

def test_v11_pipeline_is_deep(): assert len(plan()) >= 27

def test_geo_only_uses_returned_points():
    r=build_geo({'provider_results':{'AbuseIPDB':{'results':[{'ip':'1.2.3.4','countryCode':'US','isp':'ExampleNet'}]}},'dnsdumpster':{'records':{}}})
    assert r['countries'][0]['country']=='United States'
    assert r['map_points']==[]

def test_banner_normalization():
    r=build_banners({'domain':'example.com','http':{'headers':{'server':'nginx','x-powered-by':'PHP/8'}},'technology':[],'tls':{}})
    assert r['count'] >= 2

def test_url_similarity(): assert similarity('https://example.com/a','https://example.com/b')['normalized'] > 0.9

def test_typosquat_candidates(): assert any(x['technique']=='omission' for x in candidates('example.com')[:50])
