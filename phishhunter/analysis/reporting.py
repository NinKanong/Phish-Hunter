from __future__ import annotations

from collections import Counter


def _severity_for(item: dict) -> str:
    raw = str(item.get("severity", "")).lower()
    if raw in {"critical", "high", "medium", "low", "info"}:
        return raw
    score = int(item.get("score", 0) or 0)
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _confidence_for(item: dict) -> str:
    raw = str(item.get("confidence", "")).lower()
    if raw in {"high", "medium", "low"}:
        return raw
    if item.get("assessment") in {"potential_c2_candidate", "external_attacker_candidate"}:
        return "heuristic"
    return "observed"


def build_finding_catalog(result: dict) -> list[dict]:
    """Turn heterogeneous analyzer output into a stable analyst-facing finding schema."""
    findings: list[dict] = []
    counter = Counter()

    def add(name: str, category: str, severity: str, confidence: str, what: str, asset: str = "", source: str = "engine", why: str = "", next_steps: list[str] | None = None, evidence=None):
        counter[category] += 1
        findings.append({
            "id": f"K4-{category.upper()[:5]}-{counter[category]:03d}",
            "name": name,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "status": "observed" if confidence in {"observed", "high", "medium"} else "candidate",
            "what_found": what,
            "affected_asset": asset or "Not specified",
            "source": source,
            "why_it_matters": why or "Review this observation with the underlying evidence and related telemetry.",
            "recommended_next_steps": next_steps or ["Review the supporting evidence.", "Correlate with independent telemetry before taking action."],
            "evidence": evidence if isinstance(evidence, list) else [],
        })

    for raw in result.get("findings") or []:
        item = raw if isinstance(raw, dict) else {"detail": str(raw)}
        name = item.get("name") or item.get("signal") or item.get("type") or "Analysis finding"
        detail = item.get("detail") or item.get("description") or item.get("value") or str(raw)
        asset = item.get("destination") or item.get("host") or item.get("source") or item.get("domain") or ""
        add(str(name), "finding", _severity_for(item), _confidence_for(item), str(detail), str(asset), str(item.get("source", "analysis engine")), str(item.get("reason", "")), ["Open the underlying evidence.", "Pivot on related indicators."], [item])

    assessment = result.get("network_assessment") or {}
    for item in assessment.get("potential_compromised_hosts") or []:
        host = item.get("host", "unknown host")
        reasons = item.get("reasons") or []
        add(
            "Potentially compromised internal host",
            "victim",
            "critical" if int(item.get("score", 0)) >= 85 else "high" if int(item.get("score", 0)) >= 65 else "medium",
            str(item.get("confidence", "low")),
            f"Passive network evidence produced a compromise candidate for {host}. Reasons: {'; '.join(reasons) or 'correlated suspicious network activity.'}",
            host,
            "PCAP network assessment",
            "The host has one or more correlated network signals such as repeated external communications, administrative exposure, or a potential C2 flow.",
            ["Validate with EDR/process telemetry.", "Review authentication and DNS logs.", "Pivot into the associated external peers and flows."],
            item.get("potential_c2") or [],
        )
    for item in assessment.get("potential_c2_candidates") or []:
        src = item.get("internal_host", "unknown")
        dst = item.get("destination", "unknown")
        port = item.get("destination_port", "")
        reasons = item.get("reasons") or []
        add(
            "Potential command-and-control communication",
            "c2",
            "high" if int(item.get("score", 0)) >= 65 else "medium",
            "heuristic",
            f"Repeated outbound traffic from {src} to {dst}:{port} was scored as a potential C2 candidate. Reasons: {'; '.join(reasons) or 'network behavior correlation.'}",
            f"{src} → {dst}:{port}",
            "PCAP passive C2 heuristics",
            "The pattern resembles behavior that can be associated with command-and-control, but PCAP-only heuristics cannot establish maliciousness by themselves.",
            ["Inspect endpoint processes and sockets on the internal host.", "Enrich the destination IP/domain with configured threat-intelligence providers.", "Review TLS SNI/HTTP metadata and timing."],
            [item],
        )
    for item in assessment.get("external_attacker_candidates") or []:
        src = item.get("source", "unknown")
        targets = item.get("internal_targets") or []
        add(
            "External source targeting internal assets",
            "attacker-candidate",
            "high" if int(item.get("connections_to_internal", 0)) >= 10 else "medium",
            "heuristic",
            f"Public source {src} communicated with {len(targets)} internal target(s): {', '.join(targets[:12]) or 'not enumerated'}.",
            src,
            "PCAP inbound-flow heuristics",
            "Repeated external-to-internal traffic can be relevant to scanning, exploitation, remote administration, or benign published services; context is required.",
            ["Review the targeted services and ports.", "Correlate with firewall, IDS and authentication logs.", "Do not label the source malicious without corroborating evidence."],
            [item],
        )

    if not findings:
        for kind, values in (result.get("iocs") or {}).items():
            if not isinstance(values, list):
                continue
            for value in values[:50]:
                add("Observed indicator", "ioc", "info", "observed", f"The analyzer extracted a {kind} indicator from the submitted evidence.", str(value), "IOC extraction", "Indicators provide investigation pivots but are not inherently malicious.", ["Enrich the indicator.", "Search related evidence and cases."], [{"type": kind, "value": value}])

    return findings


def build_investigation_summary(result: dict) -> dict:
    catalog = build_finding_catalog(result)
    sev = Counter(x["severity"] for x in catalog)
    return {
        "finding_count": len(catalog),
        "critical": sev["critical"],
        "high": sev["high"],
        "medium": sev["medium"],
        "low": sev["low"],
        "info": sev["info"],
        "top_findings": catalog[:8],
        "analyst_disposition": "review_required" if any(x["severity"] in {"critical", "high"} for x in catalog) else "no_high_confidence_escalation",
        "confidence_note": "Confidence reflects the evidence available to this analyzer. Heuristic network observations are explicitly marked as candidates and require independent validation.",
    }
