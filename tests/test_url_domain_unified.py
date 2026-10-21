import asyncio

import phishhunter.analyzers.unified_url_domain as analyzer


def test_dns_record_dict_and_ptr_parsing():
    dns_json = {"Answer": [{"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}]}
    ptr_json = {"Answer": [{"name": "34.216.184.93.in-addr.arpa.", "type": 12, "TTL": 300, "data": "edge.example.net."}]}
    assert analyzer._record_dict(dns_json, "A")[0]["value"] == "93.184.216.34"
    assert analyzer._record_dict(ptr_json, "PTR")[0]["value"] == "edge.example.net."


def test_rdap_vcard_entity_parsing():
    sample = {
        "entities": [{
            "handle": "R1",
            "roles": ["registrar"],
            "vcardArray": ["vcard", [
                ["fn", {}, "text", "Example Registrar"],
                ["org", {}, "text", "Example Org"],
                ["email", {}, "text", "whois@example.test"],
            ]],
        }]
    }
    row = analyzer._rdap_entities(sample)[0]
    assert row["name"] == "Example Registrar"
    assert row["organization"] == "Example Org"
    assert row["email"] == "whois@example.test"


def test_tool_fabric_exceeds_200_and_marks_provider_boundary():
    fabric = analyzer.tool_fabric_status()
    assert fabric["catalog_count"] > 200
    assert fabric["boundary"]
    assert any(item["name"] == "DNSDumpster" for item in fabric["items"])
    assert any(item["name"] == "OpenAI Responses API" for item in fabric["items"])


def test_unified_pipeline_with_network_collectors_mocked(monkeypatch):
    analyzer.settings.openai_api_key = ""
    monkeypatch.setattr(analyzer, "validate_url", lambda value: value)

    async def dns(domain):
        return {
            "records": {
                "A": [{"name": domain, "ttl": 300, "value": "93.184.216.34"}],
                **{key: [] for key in ["AAAA", "CNAME", "MX", "NS", "SOA", "CAA", "SRV", "NAPTR", "DNSKEY", "DS", "RRSIG", "TLSA", "SSHFP"]},
                "TXT": [{"name": domain, "ttl": 300, "value": "v=spf1 -all"}],
            },
            "reverse_dns": {"93.184.216.34": [{"name": "34.216.184.93.in-addr.arpa.", "ttl": 300, "value": "edge.example.net."}]},
            "resolver": "mock",
        }

    async def rdap(client, path):
        return {
            "status": 200,
            "url": "https://rdap.test/" + path,
            "data": {
                "status": ["active"],
                "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
                "nameservers": [],
                "secureDNS": {},
                "notices": [],
                "remarks": [],
            },
        }

    async def ct(client, domain):
        return {"status": 200, "count": 0, "certificates": [], "names": []}

    async def http_probe(url):
        return {
            "status": "completed", "status_code": 200, "final_url": url, "headers": {}, "redirects": [], "redirect_count": 0,
            "resolutions": [], "links": [], "forms": [], "scripts": [], "html_sample": "<html><title>Example</title></html>",
        }

    async def not_configured(*args, **kwargs):
        return {"status": "not_configured", "results": []}

    async def vt(*args, **kwargs):
        return {"status": "not_configured", "provider": "VirusTotal"}

    async def hibp(*args, **kwargs):
        return {"status": "not_configured", "provider": "Have I Been Pwned", "records": []}

    async def gsb(*args, **kwargs):
        return {"status": "not_configured", "provider": "Google Safe Browsing"}

    async def dnsdump(*args, **kwargs):
        return {"status": "not_configured", "source": "DNSDumpster", "records": []}

    def tls_probe(host, port=443):
        return {
            "status": "completed", "peer_ip": "93.184.216.34", "tls_version": "TLSv1.3",
            "cipher": ["TLS_AES_128_GCM_SHA256"], "issuer": "Example CA", "san": ["example.com"],
            "sha256_fingerprint": "b" * 64,
        }

    monkeypatch.setattr(analyzer, "_dns_bundle", dns)
    monkeypatch.setattr(analyzer, "_rdap", rdap)
    monkeypatch.setattr(analyzer, "_ct_lookup", ct)
    monkeypatch.setattr(analyzer, "_http_probe", http_probe)
    monkeypatch.setattr(analyzer, "_urlscan_search", not_configured)
    monkeypatch.setattr(analyzer, "_vt_domain", vt)
    monkeypatch.setattr(analyzer, "_hibp_domain", hibp)
    monkeypatch.setattr(analyzer, "_gsb_url", gsb)
    monkeypatch.setattr(analyzer, "_dnsdumpster", dnsdump)
    monkeypatch.setattr(analyzer, "_abuseipdb", not_configured)
    monkeypatch.setattr(analyzer, "_ssl_probe", tls_probe)

    result = asyncio.run(analyzer.analyze_url_domain("https://example.com/login"))
    assert result["domain"] == "example.com"
    assert result["risk_score"] >= 0
    assert result["whois_rdap"]["registrar"] == "Example Registrar"
    assert result["dns"]["reverse_dns"]["93.184.216.34"][0]["value"] == "edge.example.net."
    assert result["graph"]["node_count"] >= 1
    assert result["graph"]["edge_count"] >= 1
    assert result["url_forensics"]["scheme"] == "https"
    assert "SPF" in result["dns_authentication"]
    assert "dmarc" in result["dns_posture"]["email_auth"]
    assert result["ip_intelligence"][0]["classification"] == "public"
    assert "package_sha256" in result["chain_of_custody"]
    assert result["self_verification"]["status"] == "verified"
    assert result["ai_analysis"]["status"] == "not_configured"
