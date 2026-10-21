from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SUPPORTED_ARTIFACTS = {
    "pcap": {"label": "PCAP / PCAPNG", "extensions": [".pcap", ".pcapng", ".cap"]},
    "zeek": {"label": "Zeek logs", "extensions": [".log", ".tsv"]},
    "suricata": {"label": "Suricata EVE JSON", "extensions": [".json"]},
    "netflow": {"label": "NetFlow / IPFIX", "extensions": [".csv", ".json"]},
    "firewall": {"label": "Firewall logs", "extensions": [".log", ".txt", ".csv", ".json"]},
    "proxy": {"label": "Proxy logs", "extensions": [".log", ".txt", ".csv", ".json"]},
    "dns": {"label": "DNS server logs", "extensions": [".log", ".txt", ".csv", ".json"]},
    "dhcp": {"label": "DHCP logs", "extensions": [".log", ".txt", ".csv", ".json"]},
}


@dataclass(slots=True)
class ArtifactInput:
    artifact_id: str
    filename: str
    artifact_type: str
    size_bytes: int
    sha256: str
    path: str


@dataclass(slots=True)
class NormalizedEvent:
    timestamp: str | None = None
    source: str = "unknown"
    event_type: str = "network"
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    hostname: str | None = None
    action: str | None = None
    severity: str | None = None
    bytes: int | None = None
    packets: int | None = None
    message: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "hostname": self.hostname,
            "action": self.action,
            "severity": self.severity,
            "bytes": self.bytes,
            "packets": self.packets,
            "message": self.message,
            "raw": self.raw,
        }
