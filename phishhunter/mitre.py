from __future__ import annotations

TECHNIQUES = {
    "T1027": "Obfuscated/Compressed Files or Information",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1105": "Ingress Tool Transfer",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1055": "Process Injection",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1047": "Windows Management Instrumentation",
    "T1112": "Modify Registry",
    "T1106": "Native API",
    "T1197": "BITS Jobs",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.004": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
}


TECHNIQUE_CONTEXT = {
    "T1027": "Encoding, packing, string transformations, and other concealment techniques can reduce static visibility.",
    "T1105": "Network transfer markers indicate possible retrieval of additional payloads or tooling.",
    "T1059.001": "PowerShell activity should be correlated with command-line parameters, parent process, and decoded content.",
    "T1218.011": "Rundll32 evidence is more meaningful when tied to a DLL path, export name, URL, or execution chain.",
    "T1055": "Process-injection markers warrant memory/process-tree correlation because strings alone do not prove injection occurred.",
}


def describe(codes: list[str] | tuple[str, ...]) -> list[dict]:
    return [
        {
            "id": code,
            "name": TECHNIQUES.get(code, "Unknown technique"),
            "context": TECHNIQUE_CONTEXT.get(code, "Analyst correlation is required before treating this as confirmed behavior."),
        }
        for code in codes
    ]


def attribution_guardrail(observed_techniques: list[str], corroborated_iocs: int = 0) -> dict:
    density = len(set(observed_techniques))
    evidence_score = min(100, density * 8 + min(corroborated_iocs, 20) * 3)
    return {
        "evidence_score": evidence_score,
        "confidence": "high" if evidence_score >= 70 else "medium" if evidence_score >= 40 else "low",
        "actor_attribution": None,
        "reason": "Actor attribution is intentionally withheld unless independently corroborated by trusted intelligence and campaign-level evidence.",
        "recommended_corroboration": [
            "Independent IOC matches from reputable threat-intelligence sources",
            "Campaign-specific infrastructure overlap",
            "Consistent TTP and malware-family evidence across multiple samples",
            "Time-bounded reporting from trusted incident-response or vendor sources",
        ],
    }
