import asyncio
import io

from fastapi.testclient import TestClient

from phishhunter.analysis.graph_builder import build_graph
from phishhunter.analyzers.file_analyzer import analyze_file
from phishhunter.enrichment.service import enrich_result
from phishhunter.main import app
from phishhunter.security.url_guard import validate_url


def test_file_name_deception_signals_are_emitted():
    result = analyze_file("invoice.pdf", b"MZ" + b"PowerShell Invoke-WebRequest " + b"A" * 100)
    assert result["metadata"]["name"]["extension_content_mismatch"] is True
    assert any(item["signal"] == "extension-content-mismatch" for item in result["evidence"])


def test_file_api_signal_detection_from_static_strings():
    result = analyze_file("sample.bin", b"VirtualAlloc WriteProcessMemory CreateRemoteThread IsDebuggerPresent")
    assert len(result["metadata"]["api_signals"]) >= 2
    assert any(item["signal"] == "suspicious-api-imports" for item in result["evidence"])


def test_graph_contains_iocs_and_attack_techniques():
    graph = build_graph(
        {
            "url": "https://example.test/login",
            "iocs": {"domains": ["example.test"], "ips": ["203.0.113.5"]},
            "mitre_techniques": [{"id": "T1059.001", "name": "PowerShell"}],
        }
    )
    kinds = {node["kind"] for node in graph["nodes"]}
    assert {"analysis", "domains", "ips", "mitre"}.issubset(kinds)
    assert len(graph["edges"]) >= 3


def test_external_enrichment_is_deterministically_disabled(monkeypatch):
    monkeypatch.setattr("phishhunter.enrichment.service.settings.enable_external_ti", False)
    result = asyncio.run(enrich_result({"hashes": {"sha256": "a" * 64}}, "file"))
    assert result["status"] == "disabled"
    assert result["providers"] == []


def test_public_status_and_method_hardening():
    with TestClient(app) as client:
        assert client.get("/status").status_code == 200
        assert client.get("/logout").status_code == 405
        assert client.get("/health").json()["version"] == "24.4.0"


def test_ssrf_guard_blocks_common_private_destinations():
    for url in ("http://127.0.0.1/", "http://10.0.0.1/", "http://169.254.169.254/"):
        try:
            validate_url(url)
        except ValueError:
            continue
        raise AssertionError(f"blocked destination accepted: {url}")
