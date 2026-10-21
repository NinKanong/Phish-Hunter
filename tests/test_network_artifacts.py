from __future__ import annotations

import ipaddress
import struct
import time

from fastapi.testclient import TestClient

from phishhunter.main import app
from phishhunter.network_artifacts.orchestrator import analyze_artifacts, detect_type
from phishhunter.network_artifacts.parsers.netflow import parse_netflow
from phishhunter.network_artifacts.parsers.suricata import parse_suricata
from phishhunter.network_artifacts.parsers.zeek import parse_zeek
from phishhunter.network_artifacts.schema import ArtifactInput


def _pcap(src="10.0.0.5", dst="8.8.8.8", sport=12345, dport=443) -> bytes:
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0,
        0,
        64,
        6,
        0,
        ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed,
    )
    tcp_header = struct.pack("!HHLLBBHHH", sport, dport, 1, 0, 0x50, 0x02, 65535, 0, 0)
    packet = ethernet + ip_header + tcp_header
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 2, len(packet), len(packet)) + packet
    return global_header + record


def test_detect_type_and_parsers():
    assert detect_type("capture.pcap", _pcap()) == "pcap"
    zeek = "#separator \\x09\n#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n1.0\t10.0.0.5\t8.8.8.8\t443\ttcp\n"
    assert parse_zeek(zeek, "conn.log")[0].src_ip == "10.0.0.5"
    suricata = '{"timestamp":"2026-10-01T00:00:00Z","event_type":"alert","src_ip":"10.0.0.5","dest_ip":"8.8.8.8","dest_port":443,"proto":"TCP","alert":{"severity":2,"signature":"test"}}\n'
    assert parse_suricata(suricata)[0].dst_port == 443
    netflow = "src_ip,dst_ip,src_port,dst_port,protocol,bytes\n10.0.0.5,8.8.8.8,1234,443,TCP,1200\n"
    assert parse_netflow(netflow)[0].bytes == 1200


def test_network_orchestrator_normalizes_pcap_events():
    data = _pcap()
    artifact = ArtifactInput("a1", "capture.pcap", "pcap", len(data), "x", "")
    result = analyze_artifacts([artifact], {"a1": data})
    assert result["summary"]["events"] >= 2
    assert "10.0.0.5" in result["iocs"]["ips"]
    assert any(node["id"] == "10.0.0.5" for node in result["network_graph"]["nodes"])
    assert result["self_verification"]["status"] == "verified"


def test_guest_network_artifact_api_end_to_end():
    data = _pcap()
    with TestClient(app) as client:
        capabilities = client.get("/api/v1/pcap/capabilities")
        assert capabilities.status_code == 200
        assert capabilities.json()["guest_analysis"] is True

        upload = client.post(
            "/api/v1/pcap/upload",
            files=[("files", ("capture.pcap", data, "application/octet-stream"))],
        )
        assert upload.status_code == 200, upload.text
        job_id = upload.json()["job_id"]

        start = client.post(f"/api/v1/pcap/analyze/{job_id}")
        assert start.status_code == 200, start.text

        final = None
        for _ in range(100):
            response = client.get(f"/api/v1/pcap/jobs/{job_id}")
            assert response.status_code == 200, response.text
            final = response.json()
            if final["status"] in {"completed", "failed"}:
                break
            time.sleep(0.03)
        assert final and final["status"] == "completed", final

        assert client.get(f"/api/v1/pcap/jobs/{job_id}/iocs").status_code == 200
        assert client.get(f"/api/v1/pcap/jobs/{job_id}/artifacts").status_code == 200
        for fmt in ("json", "ioc-csv", "events-csv", "stix", "html"):
            assert client.get(f"/api/v1/pcap/jobs/{job_id}/report/{fmt}").status_code == 200
