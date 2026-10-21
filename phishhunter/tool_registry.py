from __future__ import annotations

TOOL_MODULES = {
    "email_analyst": "phishhunter.email_analyst",
    "url_domain_analyst": "phishhunter.url_domain_analyst",
    "file_analyst": "phishhunter.file_analyst",
    "ip_analyst": "phishhunter.ip_analyst",
    "network_artifacts": "phishhunter.network_artifacts",
    "malware_analyst": "phishhunter.malware_analyst",
    "ransomware_analyst": "phishhunter.ransomware_analyst",
    "ioc_analyst": "phishhunter.ioc_analyst",
    "phishing_kit_analyst": "phishhunter.phishing_kit_analyst",
    "threat_intelligence": "phishhunter.threat_intelligence",
    "sandbox": "phishhunter.sandbox",
    "reports": "phishhunter.reports",
    "campaigns": "phishhunter.campaigns",
    "threat_actors": "phishhunter.threat_actors",
    "ioc_graph": "phishhunter.ioc_graph",
    "threat_feeds": "phishhunter.threat_feeds",
}

def registry_manifest() -> dict:
    return {"count": len(TOOL_MODULES), "modules": TOOL_MODULES.copy()}
