from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress
import math
import statistics
from typing import Any


def _private(value: str | None) -> bool:
    try:
        return ipaddress.ip_address(value).is_private if value else False
    except ValueError:
        return False


def _global(value: str | None) -> bool:
    try:
        return ipaddress.ip_address(value).is_global if value else False
    except ValueError:
        return False


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def build_findings(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    by_flow: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    dns_names: list[str] = []
    for event in events:
        key = (event.get("src_ip"), event.get("dst_ip"), event.get("dst_port"), event.get("protocol"))
        if key[0] or key[1]:
            by_flow[key].append(event)
        host = event.get("hostname")
        if host:
            dns_names.append(str(host).rstrip("."))
        if event.get("severity") and str(event["severity"]).lower() in {"1", "critical", "high"}:
            findings.append({"name": "High-severity network alert", "severity": "high", "confidence": 90, "score": 75, "reason": event.get("message") or "High-severity alert observed", "evidence": event})
    for key, rows in by_flow.items():
        src, dst, port, proto = key
        if _private(src) and _global(dst) and len(rows) >= 5:
            score = 20
            reasons = ["repeated internal-to-public communication"]
            if port in {4444, 5555, 1337, 31337, 9001}:
                score += 35; reasons.append("commonly abused remote-control port")
            if port and port not in {53, 80, 123, 443, 25, 110, 143, 587}:
                score += 10; reasons.append("non-standard outbound destination port")
            findings.append({"name": "Potential C2 communication", "severity": "high" if score >= 50 else "medium", "confidence": 55, "score": min(score, 100), "reason": "; ".join(reasons), "evidence": {"flow": key, "events": rows[:20]}})
    for host in sorted(set(dns_names)):
        labels = host.split(".")
        longest = max((len(x) for x in labels), default=0)
        ent = max((_entropy(x) for x in labels), default=0)
        if longest >= 35 or ent >= 4.2:
            findings.append({"name": "DNS tunneling candidate", "severity": "medium", "confidence": 55, "score": 50, "reason": f"long/high-entropy DNS label observed: {host}", "evidence": {"hostname": host, "entropy": round(ent, 3), "longest_label": longest}})
    return findings


def build_graph(events: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: Counter[tuple[str, str, str]] = Counter()
    for event in events:
        src, dst = event.get("src_ip"), event.get("dst_ip")
        if src:
            nodes.setdefault(src, {"id": src, "type": "host", "scope": "private" if _private(src) else "public" if _global(src) else "other"})
        if dst:
            nodes.setdefault(dst, {"id": dst, "type": "host", "scope": "private" if _private(dst) else "public" if _global(dst) else "other"})
        if src and dst:
            edges[(src, dst, str(event.get("protocol") or "unknown"))] += 1
    return {"nodes": list(nodes.values()), "edges": [{"source": s, "target": d, "protocol": p, "weight": n} for (s, d, p), n in edges.items()]}


def build_summary(events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    protocols = Counter(str(x.get("protocol") or "unknown") for x in events)
    sources = Counter(str(x.get("source") or "unknown") for x in events)
    endpoints = Counter()
    for x in events:
        for key in ("src_ip", "dst_ip"):
            if x.get(key): endpoints[str(x[key])] += 1
    score = max([int(x.get("score", 0) or 0) for x in findings] or [0])
    return {"events": len(events), "findings": len(findings), "risk_score": min(score, 100), "protocols": protocols, "sources": sources, "top_endpoints": endpoints.most_common(20)}
