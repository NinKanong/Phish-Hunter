from phishhunter.url_domain_analyst.geo.earth_observatory import build


def test_earth_observatory_contains_requested_domain_checks():
    dns={"records":{"A":[{"value":"203.0.113.10"}],"MX":[{"value":"mx.example.test"}],"TXT":[{"value":"v=spf1 -all"}],"CAA":[{"value":"0 issue \"letsencrypt.org\""}]},"dnssec":{"status":"secure"}}
    surface={"a_records":[{"host":"example.test","ip":"203.0.113.10","asn":"64500","asn_name":"Example Net","ptr":"edge.example.test","reverse_ip_neighbor_count":2}]}
    geo={"map_points":[{"ip":"203.0.113.10","lat":40.7,"lon":-74.0,"country":"United States","country_code":"US","source":"fixture"}],"countries":[{"country":"United States","count":1}],"country_layers":[{"code":"US","name":"United States","lat":39.8,"lon":-98.6,"count":1}]}
    branches={"locations":[{"name":"Example HQ","city":"New York","country":"United States","lat":40.7,"lon":-74.0,"source":"fixture"}],"count":1}
    out=build({"domain":"example.test","technology":["nginx"],"certificate_reuse":{},"reputation":{}},geo,branches,surface,dns,{"status":"ok"},{"certificate_count":1,"discovered_names":["example.test"]},{"status_code":200,"headers":{"content-type":"text/html"}},{"protocol":"TLS"},{"status":"secure"},{"spf":"ok"},{"detected":True,"provider":"Example CDN"},{"asn":"64500"},{"status":"active"},{"provider":"Example"},{"observed":True},{"observations":[]},{"company_name":"Example"})
    names={x["name"] for x in out["checks"]}
    for expected in ["DNS Records","DNS Health","IP & ISP","Reverse DNS","CDN Bypass","MX Analysis","SPF Chain","Mail Security","RDAP / WHOIS","BGP / ASN","SSL / crt.sh","Reverse IP","DNSSEC Chain","HTTP / HTTPS","Web Policy"]:
        assert expected in names
    assert out["check_summary"]["total"] >= 15
    assert len(out["entities"]) >= 1
    assert out["entities"][0]["precision"] == "provider-coordinate"


def test_earth_does_not_create_coordinates_from_a_country_string():
    out=build(
        {"domain":"example.test"},
        {"countries":[{"country":"United States","count":1}],"country_layers":[{"code":"US","name":"United States","lat":39.8,"lon":-98.6,"count":1}]},
        {"locations":[],"count":0},
        {"a_records":[]},
        {"records":{}},
        {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}
    )
    assert out["entities"] == []
    assert out["country_layers"]
