from __future__ import annotations

TOOL_KEY = 'ip-analyst'
DISPLAY_NAME = 'IP Analyst'
MISSION = 'Infrastructure and reputation profiling for IPv4/IPv6 indicators with reverse DNS, ownership and relationship pivots.'
CAPABILITIES = ['IPv4/IPv6 validation', 'Public/private/reserved classification', 'PTR/reverse-DNS lookup', 'ASN/organization enrichment slots', 'BGP prefix context', 'WHOIS/RDAP slots', 'Historical passive-DNS pivots', 'Certificate SAN pivots', 'Co-hosting relationship discovery', 'Open-port evidence slots', 'TLS service posture', 'Geolocation provider boundary', 'Abuse/reputation matrix', 'Malware/URL relationship pivots', 'IOC normalization', 'Risk scoring', 'Evidence confidence', 'Graph-ready relationships', 'IR pivot checklist']
EVIDENCE_SOURCES = ['RDAP/WHOIS', 'DNS PTR', 'BGP/ASN providers', 'Certificate Transparency', 'Shodan/Censys', 'AbuseIPDB', 'MISP/OpenCTI']
INTEGRATIONS = ['Shodan', 'Censys', 'GreyNoise', 'AbuseIPDB', 'SecurityTrails', 'DomainTools', 'BGPView', 'RIPEstat', 'ARIN', 'APNIC', 'LACNIC', 'AFRINIC', 'MaxMind GeoIP', 'VirusTotal', 'MISP', 'OpenCTI', 'Netlas']
SAFETY_BOUNDARY = "Evidence-first analysis; no fabricated provider results, unsupported attribution, arbitrary command execution from the web path, or dynamic detonation inside the application process."

def manifest() -> dict:
    return {"key": TOOL_KEY, "title": DISPLAY_NAME, "mission": MISSION, "capabilities": CAPABILITIES, "evidence_sources": EVIDENCE_SOURCES, "integrations": INTEGRATIONS, "safety_boundary": SAFETY_BOUNDARY}
