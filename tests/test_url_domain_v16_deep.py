import asyncio

from phishhunter.url_domain_analyst.deep_intelligence.normalization import normalize_target
from phishhunter.url_domain_analyst.deep_intelligence.field_inventory import build as build_inventory
from phishhunter.url_domain_analyst.deep_intelligence.country_matrix import build as build_country
from phishhunter.url_domain_analyst.deep_intelligence.service_matrix import build as build_services

def test_target_normalization_worldwide_idna_and_url():
    x=normalize_target("https://ExAmple.com:443/login?q=a")
    assert x["hostname"]=="example.com"
    assert x["is_url"] is True
    y=normalize_target("bücher.de")
    assert y["hostname"].startswith("xn--")

def test_deep_matrices_are_safe_with_sparse_results():
    result={"dns":{"records":{"A": [{"name":"example.com","value":"192.0.2.10"}]}},"http":{},"tls":{},"whois_rdap":{}}
    inv=build_inventory(result)
    assert inv["observed_counts"]["dns_records"]==1
    assert build_country({"url_domain_vnext":{"attack_surface":{"a_records":[]}}})["countries"]==[]
    assert build_services({"url_domain_vnext":{"services_banners":{"rows":[]}}})["products"]==[]
