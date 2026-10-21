from __future__ import annotations

from collections import defaultdict
from typing import Any


def correlate(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Cross-artifact correlation without asserting attribution."""
    by_key: dict[str, set[str]] = defaultdict(set)
    ip_hosts: dict[str, set[str]] = defaultdict(set)
    for event in events:
        source = str(event.get("source") or "unknown")
        for field in ("src_ip", "dst_ip"):
            ip = event.get(field)
            if ip:
                by_key[str(ip)].add(source)
        ip = event.get("src_ip")
        host = event.get("hostname")
        if ip and host:
            ip_hosts[str(ip)].add(str(host))
    return {
        "artifact_source_pivots": [{"indicator": k, "sources": sorted(v)} for k, v in by_key.items() if len(v) > 1][:5000],
        "ip_hostname_resolution": [{"ip": k, "hostnames": sorted(v)} for k, v in ip_hosts.items()][:5000],
        "cross_source_count": sum(1 for v in by_key.values() if len(v) > 1),
        "limitations": "Correlation links observations by shared indicators and does not establish causality or attribution.",
    }
