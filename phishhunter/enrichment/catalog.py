from __future__ import annotations

PROVIDERS = [
    ("VirusTotal", "hash,url,domain,ip"),
    ("urlscan.io", "url,domain"),
    ("AbuseIPDB", "ip"),
    ("Shodan", "ip"),
    ("Censys", "ip,domain"),
    ("MISP", "ip,domain,url,hash,email"),
    ("AlienVault OTX", "ip,domain,url,hash"),
    ("ThreatFox", "ip,domain,url,hash"),
    ("MalwareBazaar", "hash"),
    ("Hybrid Analysis", "hash"),
    ("Joe Sandbox", "hash,url"),
    ("ANY.RUN", "hash,url"),
    ("PhishTank", "url"),
    ("OpenPhish", "url"),
    ("Google Safe Browsing", "url"),
    ("Have I Been Pwned", "email"),
    ("WHOISXML", "domain,ip"),
    ("SecurityTrails", "domain,ip"),
    ("PassiveTotal", "domain,ip"),
    ("GreyNoise", "ip"),
    ("Spamhaus", "ip,domain"),
    ("IPQualityScore", "ip,url,email"),
    ("Cisco Talos", "ip,domain"),
    ("Microsoft Defender TI", "ip,domain,url,hash"),
    ("IBM X-Force", "ip,domain,url,hash"),
    ("Recorded Future", "ip,domain,url,hash"),
]


def catalog() -> list[dict[str, object]]:
    configured = {"VirusTotal": "VIRUSTOTAL_API_KEY", "urlscan.io": "URLSCAN_API_KEY"}
    return [
        {
            "provider": name,
            "indicator_types": types.split(","),
            "status": "configured-connector" if name in configured else "not-configured",
            "credential_env": configured.get(name),
            "results_are_faked": False,
        }
        for name, types in PROVIDERS
    ]
