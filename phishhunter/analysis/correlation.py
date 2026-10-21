from __future__ import annotations

from collections import Counter


APT_FOCUSED_CONTEXTS = {
    "T1027": "possible concealment or staging",
    "T1059.001": "PowerShell execution evidence",
    "T1059.003": "Windows command execution evidence",
    "T1218.005": "Mshta proxy-execution evidence",
    "T1218.010": "Regsvr32 proxy-execution evidence",
    "T1218.011": "Rundll32 proxy-execution evidence",
    "T1055": "process-injection indicator requiring runtime correlation",
    "T1105": "possible payload retrieval or ingress transfer",
    "T1112": "registry-modification indicator",
    "T1053.005": "scheduled-task persistence indicator",
    "T1547": "boot/logon persistence indicator",
}


def _ioc_count(iocs: dict[str, list[str]]) -> int:
    return sum(len(values) for values in iocs.values())


def correlate_evidence(iocs: dict[str, list[str]], techniques: list[dict], artifacts: list[dict]) -> dict:
    technique_ids = [item.get("id") for item in techniques if item.get("id")]
    technique_counter = Counter(technique_ids)
    clusters: list[dict] = []

    def add_cluster(name: str, level: str, reason: str, evidence: list[str]):
        if evidence:
            clusters.append({"name": name, "level": level, "reason": reason, "evidence": evidence[:20]})

    add_cluster(
        "Credential-harvest pattern",
        "high",
        "Observed credential-related content combined with delivery or link evidence.",
        ["credential-language"] if any("1059.001" == value for value in technique_ids) else [],
    )
    add_cluster(
        "Script / LOLBin execution",
        "high",
        "Script interpreters or signed Windows proxy binaries appear in static evidence.",
        [APT_FOCUSED_CONTEXTS[item] for item in sorted(set(technique_ids)) if item in APT_FOCUSED_CONTEXTS and item.startswith(("T1059", "T1218"))],
    )
    add_cluster(
        "Persistence indicators",
        "high",
        "Static evidence suggests scheduled-task or boot/logon persistence behavior.",
        [APT_FOCUSED_CONTEXTS[item] for item in sorted(set(technique_ids)) if item in {"T1053.005", "T1547", "T1547.004"}],
    )
    add_cluster(
        "Defense-evasion / staging indicators",
        "medium",
        "Obfuscation, transfer, archive, or injection-related evidence is present.",
        [APT_FOCUSED_CONTEXTS[item] for item in sorted(set(technique_ids)) if item in {"T1027", "T1105", "T1055", "T1140"}],
    )

    corroboration = {
        "ioc_count": _ioc_count(iocs),
        "unique_domains": len(set(iocs.get("domains", []))),
        "unique_ips": len(set(iocs.get("ips", []))),
        "unique_hashes": len(set(iocs.get("hashes", []))),
        "technique_count": len(set(technique_ids)),
        "artifact_evidence_count": len(artifacts),
        "external_ti_required_for_attribution": True,
    }
    signal_density = min(100, corroboration["technique_count"] * 10 + min(corroboration["ioc_count"], 20) * 2)
    posture = "elevated" if signal_density >= 60 else "moderate" if signal_density >= 30 else "limited"
    return {
        "signal_density": signal_density,
        "investigation_posture": posture,
        "technique_frequency": dict(sorted(technique_counter.items())),
        "evidence_clusters": clusters,
        "corroboration": corroboration,
        "actor_attribution": {
            "status": "withheld",
            "basis": "Observable evidence can support APT-oriented triage, but actor identity requires independent campaign-level corroboration.",
            "next_evidence": [
                "Compare hashes and domains with trusted threat-intelligence feeds.",
                "Correlate timestamps and infrastructure reuse across independent incidents.",
                "Compare multiple samples for stable TTP, config, and malware-family traits.",
                "Use endpoint, DNS, proxy, identity, and mail telemetry before drawing attribution conclusions.",
            ],
        },
    }
