from phishhunter.url_domain_analyst.attack_surface import build

def test_attack_surface_resolver_fallback():
    result={"domain":"example.com","dns":{"records":{"A":[{"name":"example.com","value":"93.184.216.34","ttl":300}],"AAAA":[]}},"dnsdumpster":{"status":"not_configured","records":{}}}
    s=build(result)
    assert s["a_records"][0]["source"]=="DNS-over-HTTPS"
    assert s["a_records"][0]["ip"]=="93.184.216.34"

def test_dataset_revip_is_limited_to_returned_rows():
    result={"domain":"example.com","dns":{"records":{"A":[{"name":"a.example.com","value":"192.0.2.1"},{"name":"b.example.com","value":"192.0.2.1"}]}},"dnsdumpster":{"status":"not_configured","records":{}}}
    s=build(result)
    assert all(x["revip_status"]=="dataset-correlation" for x in s["a_records"])
