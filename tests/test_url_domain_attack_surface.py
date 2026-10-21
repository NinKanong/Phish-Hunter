from phishhunter.url_domain_analyst.attack_surface import build


def test_dnsdumpster_attack_surface_matches_provider_fields():
    result = {
        "domain": "example.com",
        "dnsdumpster": {
            "status": "completed",
            "source": "DNSDumpster",
            "records": {
                "a": [
                    {
                        "host": "portal.example.com",
                        "ips": [
                            {
                                "ip": "203.0.113.10",
                                "asn": "64500",
                                "asn_name": "ExampleNet",
                                "asn_range": "203.0.113.0/24",
                                "country": "United States",
                                "country_code": "US",
                                "ptr": "edge.example.net",
                                "banners": {
                                    "http": {"apps": ["nginx"], "server": "nginx", "title": "403 Forbidden"},
                                    "https": {"apps": ["nginx"], "cn": "portal.example.com", "server": "nginx", "version": "1.25"},
                                },
                            }
                        ],
                    }
                ],
                "ns": [],
                "mx": [],
                "cname": [],
                "txt": [],
            },
        },
        "ip_intelligence": [],
        "network_associations": {"current_ips": ["203.0.113.10"]},
    }
    surface = build(result)
    assert surface["summary"]["a_records"] == 1
    assert surface["summary"]["unique_ips"] == 1
    row = surface["a_records"][0]
    assert row["host"] == "portal.example.com"
    assert row["ip"] == "203.0.113.10"
    assert row["asn"] == "64500"
    assert row["asn_name"] == "ExampleNet"
    assert row["ptr"] == "edge.example.net"
    assert row["country"] == "United States"
    assert row["open_services"]
    assert any(b["protocol"] == "https" and b["version"] == "1.25" for b in row["banners"])


def test_reverse_ip_is_explicitly_dataset_scoped():
    base = {
        "dnsdumpster": {
            "status": "completed",
            "records": {"a": [
                {"host": "a.example.com", "ips": [{"ip": "203.0.113.10", "country": "US"}]},
                {"host": "b.example.com", "ips": [{"ip": "203.0.113.10", "country": "US"}]},
            ]},
        }
    }
    surface = build(base)
    rows = {r["host"]: r for r in surface["a_records"]}
    assert rows["a.example.com"]["revip_status"] == "dataset-correlation"
    assert rows["b.example.com"]["reverse_ip_neighbor_count"] == 1
