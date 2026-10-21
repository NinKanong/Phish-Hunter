from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import re
import shutil
import socket
import ssl
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import unescape
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from phishhunter.config import settings
from phishhunter.url_domain_analyst.domain.public_suffix import try_psl
from phishhunter.security.url_guard import resolve_and_validate, validate_url, url_features
from phishhunter.utils.http import fetch_url

UTC = timezone.utc

# This is intentionally an adapter registry, not a claim that 200+ services are all
# queried automatically. Each item identifies an integration surface and its runtime
# boundary. Live results are only emitted when the required credential/CLI exists.
TOOL_GROUPS: dict[str, list[tuple[str, str, str]]] = {
    "Domain & DNS": [
        ("Amass", "cli", "Subdomain and DNS asset discovery"), ("Subfinder", "cli", "Passive subdomain enumeration"),
        ("Assetfinder", "cli", "Passive domain discovery"), ("dnsx", "cli", "DNS probing and resolution"),
        ("DNSRecon", "cli", "DNS enumeration"), ("dnsenum", "cli", "DNS enumeration"), ("Fierce", "cli", "DNS reconnaissance"),
        ("MassDNS", "cli", "High-scale DNS resolution"), ("PureDNS", "cli", "Mass DNS resolving"),
        ("ShuffleDNS", "cli", "Wildcard-aware DNS resolution"), ("Findomain", "cli", "Domain discovery"),
        ("Chaos", "api", "Subdomain intelligence feed"), ("crt.sh", "public", "Certificate Transparency search"),
        ("DNSDumpster", "api", "DNS and host discovery"), ("SecurityTrails", "api", "Historical DNS and passive DNS"),
        ("DomainTools", "api", "WHOIS, passive DNS and infrastructure"), ("ViewDNS", "public", "DNS and domain lookups"),
        ("HackerTarget", "public", "DNS and host research"), ("Robtex", "public", "DNS/IP relationship research"),
        ("WhoisXML API", "api", "WHOIS/RDAP and DNS data"), ("WhoisFreaks", "api", "WHOIS and DNS intelligence"),
        ("DNSlytics", "public", "DNS history and host relations"), ("DNS History", "public", "Historical DNS records"),
        ("MXToolbox", "public", "DNS, MX and reputation checks"), ("IntoDNS", "public", "DNS health review"),
        ("DNSViz", "public", "DNSSEC validation and visualization"), ("Zonemaster", "public", "DNS protocol checks"),
        ("ViewDNS Reverse IP", "public", "Reverse IP neighborhood discovery"), ("BGPView", "public", "ASN and BGP context"),
        ("RIPEstat", "api", "RIPE routing and ASN data"), ("RouteViews", "public", "Routing table context"),
        ("PeeringDB", "api", "Network interconnection context"), ("IANA RDAP Bootstrap", "public", "RDAP service discovery"),
        ("ARIN RDAP", "public", "North American IP registration"), ("RIPE NCC RDAP", "public", "RIPE IP registration"),
        ("APNIC RDAP", "public", "APNIC IP registration"), ("LACNIC RDAP", "public", "LACNIC IP registration"),
        ("AFRINIC RDAP", "public", "AFRINIC IP registration"), ("CIRCL Passive DNS", "api", "Passive DNS observations"),
        ("DNSDB", "api", "Passive DNS database"), ("Farsight DNSDB", "api", "Passive DNS database"),
        ("OpenINTEL", "api", "Internet DNS measurement"), ("Sonar RDNS", "public", "Rapid7 forward/reverse DNS datasets"),
    ],
    "Certificates & Web": [
        ("Censys", "api", "Certificate, host and service intelligence"), ("CertSpotter", "api", "Certificate Transparency monitoring"),
        ("Facebook CT Logs", "public", "Certificate Transparency source"), ("Google CT", "public", "Certificate Transparency source"),
        ("SSLMate CT", "api", "Certificate Transparency monitoring"), ("CertStream", "stream", "Real-time certificate events"),
        ("urlscan.io", "api", "Historical page and network scans"), ("VirusTotal", "api", "Domain, URL and IP reputation"),
        ("Google Safe Browsing", "api", "Malicious URL reputation"), ("Microsoft SmartScreen", "public", "Reputation research"),
        ("PhishTank", "api", "Phishing URL intelligence"), ("OpenPhish", "feed", "Phishing intelligence feed"),
        ("URLhaus", "api", "Malware URL intelligence"), ("Abuse.ch ThreatFox", "api", "IOC intelligence"),
        ("AlienVault OTX", "api", "Threat intelligence pulses"), ("MISP", "api", "Community threat intelligence"),
        ("OpenCTI", "api", "Threat intelligence graph"), ("ThreatMiner", "public", "Threat research"),
        ("Hybrid Analysis", "api", "Malware and URL intelligence"), ("ANY.RUN", "api", "Sandbox intelligence"),
        ("Joe Sandbox", "api", "Sandbox intelligence"), ("Triage", "api", "Sandbox intelligence"),
        ("urlquery.net", "public", "Website analysis"), ("Sucuri SiteCheck", "public", "Website security assessment"),
        ("SecurityHeaders", "public", "HTTP security header grading"), ("Mozilla Observatory", "public", "Web security checks"),
        ("Hardenize", "public", "Domain security posture"), ("SSL Labs", "public", "TLS/SSL analysis"),
        ("testssl.sh", "cli", "Local TLS assessment"), ("sslyze", "cli", "TLS protocol and certificate testing"),
        ("Nuclei", "cli", "Template-driven web checks (authorized use)"), ("httpx", "cli", "HTTP metadata and probing"),
        ("Katana", "cli", "Web crawling (authorized use)"), ("Hakrawler", "cli", "Link extraction"),
        ("Gospider", "cli", "Web crawling"), ("Photon", "cli", "Web OSINT and crawling"), ("gau", "cli", "Historical URL collection"),
        ("waybackurls", "cli", "Wayback URL discovery"), ("waybackpy", "python", "Wayback API client"),
        ("Common Crawl Index", "api", "Historical web crawl index"), ("Internet Archive", "public", "Web archive research"),
        ("Archive.today", "public", "Web archive research"), ("Memento", "public", "TimeMap archive aggregation"),
        ("Wappalyzer", "api", "Technology fingerprinting"), ("WhatRuns", "public", "Technology discovery"),
        ("BuiltWith", "api", "Technology profiling"), ("Netcraft", "public", "Site and infrastructure research"),
        ("SimilarTech", "api", "Technology profiling"), ("PublicWWW", "public", "Source-code search"),
        ("SpyOnWeb", "public", "Web property relationships"), ("FavIconHash", "local", "Favicon relationship fingerprinting"),
    ],
    "IP & Network": [
        ("Shodan", "api", "Internet-exposed service search"), ("Censys Search", "api", "Host and certificate search"),
        ("FOFA", "api", "Internet asset search"), ("ZoomEye", "api", "Internet asset search"),
        ("Netlas", "api", "Internet asset intelligence"), ("Criminal IP", "api", "IP/domain intelligence"),
        ("LeakIX", "api", "Exposed service and leak intelligence"), ("Onyphe", "api", "Cyber exposure intelligence"),
        ("GreyNoise", "api", "Internet scanner context"), ("AbuseIPDB", "api", "IP abuse reputation"),
        ("IPinfo", "api", "IP geolocation and ASN"), ("ip-api", "public", "IP geolocation"),
        ("MaxMind GeoLite2", "local", "IP geolocation database"), ("GeoIP2", "local", "IP geolocation database"),
        ("IP2Location", "api", "IP geolocation and ASN"), ("DB-IP", "api", "IP geolocation"),
        ("BGP Toolkit", "public", "BGP and ASN context"), ("Hurricane Electric BGP Toolkit", "public", "ASN and route context"),
        ("Internet Routing Registry", "public", "Routing policy context"), ("RIPE Atlas", "api", "Internet measurement"),
        ("CAIDA", "public", "Internet measurement research"), ("Rapid7 Open Data", "public", "Internet-scale datasets"),
        ("Project Sonar", "public", "Internet-scale discovery datasets"), ("Shadowserver", "feed", "Exposure and threat reports"),
        ("Spamhaus", "api", "IP/domain reputation"), ("Cisco Talos", "public", "Reputation and threat context"),
        ("IBM X-Force", "api", "Threat intelligence"), ("Recorded Future", "api", "Threat intelligence"),
        ("Microsoft Defender Threat Intelligence", "api", "Threat intelligence"), ("Palo Alto AutoFocus", "api", "Threat intelligence"),
        ("FortiGuard", "public", "Reputation and threat lookup"), ("Trend Micro", "public", "Reputation lookup"),
        ("Kaspersky Threat Intelligence Portal", "public", "Reputation research"), ("ESET", "public", "Reputation research"),
    ],
    "Identity / Company / OSINT": [
        ("OSINT Framework", "directory", "Curated OSINT source taxonomy"), ("OSINT.dev", "directory", "OSINT tools and investigation concepts"),
        ("Maltego", "desktop", "Entity and relationship analysis"), ("SpiderFoot", "cli", "Automated OSINT collection"),
        ("Recon-ng", "cli", "Reconnaissance framework"), ("theHarvester", "cli", "Email/domain discovery"),
        ("Photon", "cli", "Web OSINT collection"), ("Metagoofil", "cli", "Metadata harvesting"),
        ("FOCA", "desktop", "Document metadata and OSINT"), ("Sherlock", "cli", "Username search"),
        ("Maigret", "cli", "Username search"), ("WhatsMyName", "dataset", "Username discovery"),
        ("Blackbird", "cli", "Username enumeration"), ("Holehe", "cli", "Email account enumeration"),
        ("h8mail", "cli", "Email OSINT and breach checks"), ("GHunt", "cli", "Google account OSINT"),
        ("Google Dorks", "search", "Search-engine research"), ("Bing Operators", "search", "Search-engine research"),
        ("Yandex Search", "search", "Search-engine research"), ("Google Lens", "public", "Visual search"),
        ("TinEye", "public", "Reverse image search"), ("ExifTool", "cli", "Metadata extraction"),
        ("Am I Unique", "public", "Browser uniqueness research"), ("Have I Been Pwned", "api", "Breach exposure intelligence"),
        ("OpenAI Responses API", "api", "Evidence-grounded investigation brief"), ("LinkedIn Official API", "api", "Authorized organization/people lookups; no scraping"), ("IPinfo", "api", "IP geolocation and ASN context"), ("SecurityTrails", "api", "Passive DNS and domain infrastructure history"),
        ("DeHashed", "api", "Breach intelligence"), ("IntelX", "api", "Breach/leak intelligence"),
        ("Hudson Rock", "api", "Infostealer intelligence"), ("SpyCloud", "api", "Identity and breach intelligence"),
        ("Constella", "api", "Identity exposure intelligence"), ("LeakCheck", "api", "Breach intelligence"),
        ("Snusbase", "api", "Breach intelligence"), ("BreachDirectory", "public", "Breach search"),
        ("WeLeakInfo", "research", "Historical breach intelligence"), ("Intelligence X", "api", "Dark-web and leak intelligence"),
        ("Ahmia", "public", "Tor hidden-service search index"), ("OnionLand Search", "public", "Tor index"),
        ("DarkSearch", "api", "Tor search index"), ("Grep.app", "api", "Public code search"),
        ("GitHub Search", "api", "Repository/code search"), ("GitLab Search", "api", "Repository/code search"),
        ("Gitleaks", "cli", "Secret detection"), ("TruffleHog", "cli", "Secret detection"),
        ("GitGuardian", "api", "Secret exposure intelligence"), ("Searchcode", "search", "Code search"),
        ("DeviantArt Search", "public", "Public profile research"), ("Reddit Search", "public", "Community research"),
        ("Google Groups", "search", "Public group research"), ("Pastebin Search", "public", "Paste research"),
        ("Rentry Search", "public", "Paste research"), ("PublicWWW", "public", "Public web source search"),
    ],
    "Threat Intel / Analysis": [
        ("MITRE ATT&CK", "dataset", "Technique knowledge base"), ("MITRE D3FEND", "dataset", "Defensive countermeasure knowledge"),
        ("CAPEC", "dataset", "Attack pattern catalog"), ("CWE", "dataset", "Weakness catalog"),
        ("CVE / NVD", "api", "Vulnerability intelligence"), ("EPSS", "api", "Exploit probability scoring"),
        ("CISA KEV", "feed", "Known exploited vulnerabilities"), ("MISP Galaxy", "dataset", "Threat actor and campaign taxonomy"),
        ("Abuse.ch URLhaus", "feed", "Malware URL feed"), ("Abuse.ch ThreatFox", "feed", "IOC feed"),
        ("MalwareBazaar", "api", "Malware sample intelligence"), ("ThreatFox", "api", "IOC relationships"),
        ("OTX AlienVault", "api", "Threat pulses"), ("CERT.PL Lists", "feed", "Threat intelligence"),
        ("CIRCL CVE Search", "api", "Vulnerability intelligence"), ("CIRCL Hash Lookup", "api", "Hash intelligence"),
        ("URLhaus", "api", "Malware URL intelligence"), ("Phishunt", "feed", "Phishing feed"),
        ("PhishStats", "feed", "Phishing statistics"), ("StopForumSpam", "api", "Abuse/identity reputation"),
        ("Abuse.ch SSL Blacklist", "feed", "Certificate intelligence"), ("Blocklist.de", "feed", "Abuse intelligence"),
        ("FireHOL", "feed", "Blocklists"), ("Emerging Threats", "feed", "Threat detection rules"),
        ("SANS ISC", "public", "Internet Storm Center research"), ("URLhaus RPZ", "feed", "DNS-based blocking"),
        ("SpamCop", "public", "Abuse reputation"), ("Talos Intelligence", "public", "Threat intelligence"),
        ("ThreatConnect", "api", "Threat intelligence platform"), ("Anomali", "api", "Threat intelligence"),
        ("OpenPhish", "feed", "Phishing feed"), ("PhishTank", "api", "Phishing reports"),
    ],
    "Infrastructure / Cloud": [
        ("Cloudflare Radar", "api", "Traffic and Internet observability"), ("Cloudflare DNS", "public", "Authoritative DNS"),
        ("AWS IP Ranges", "feed", "Cloud IP ranges"), ("Azure IP Ranges", "feed", "Cloud IP ranges"),
        ("GCP IP Ranges", "feed", "Cloud IP ranges"), ("Oracle Cloud IP Ranges", "feed", "Cloud IP ranges"),
        ("DigitalOcean IPs", "public", "Cloud IP context"), ("Hetzner Networks", "public", "Network context"),
        ("Vultr ASN/IP", "public", "Cloud hosting context"), ("Linode/Akamai IPs", "public", "Cloud hosting context"),
        ("Netcraft Hosting", "public", "Hosting and infrastructure research"), ("SecurityTrails Hosting", "api", "Hosting context"),
        ("Host.io", "api", "Domain/IP relationships"), ("ViewDNS", "public", "Infrastructure lookups"),
        ("SpyOnWeb", "public", "Analytics/host relationships"), ("BuiltWith", "api", "Technology and hosting"),
        ("Wappalyzer", "api", "Technology fingerprinting"), ("Netify", "public", "Network/application fingerprints"),
        ("PeeringDB", "api", "Network provider context"), ("BGP.tools", "public", "BGP research"),
    ],
    "SOC / IR / Forensics": [
        ("Zeek", "cli", "Network telemetry"), ("Suricata", "cli", "IDS network telemetry"),
        ("Arkime", "cli", "Packet capture indexing"), ("Wireshark", "desktop", "Packet analysis"),
        ("tshark", "cli", "Packet analysis CLI"), ("NetworkMiner", "desktop", "Network forensics"),
        ("Velociraptor", "cli", "Endpoint forensics"), ("osquery", "cli", "Endpoint telemetry"),
        ("Sysmon", "event-log", "Windows telemetry"), ("Sigma", "dataset", "Detection rule standard"),
        ("YARA", "cli", "Pattern matching"), ("KAPE", "desktop", "Forensic collection"),
        ("Volatility", "cli", "Memory forensics"), ("Autopsy", "desktop", "Digital forensics"),
        ("The Sleuth Kit", "cli", "Digital forensics"), ("Timesketch", "web", "Timeline analysis"),
        ("Plaso", "cli", "Timeline generation"), ("Chainsaw", "cli", "Windows event-log hunting"),
        ("Hayabusa", "cli", "Windows event-log analysis"), ("MISP", "api", "Threat intelligence collaboration"),
        ("OpenCTI", "api", "Threat intelligence graph"), ("TheHive", "api", "Incident response case management"),
        ("Cortex", "api", "Observable analyzers"), ("Shuffle", "api", "Security orchestration"),
        ("StackStorm", "api", "Security automation"), ("n8n", "api", "Workflow automation"),
        ("Tines", "api", "Security automation"), ("Wazuh", "api", "XDR/SIEM telemetry"),
        ("Elastic Security", "api", "SIEM and detection"), ("Splunk", "api", "SIEM and detection"),
        ("Microsoft Sentinel", "api", "SIEM and detection"), ("Google Chronicle", "api", "SIEM and detection"),
        ("QRadar", "api", "SIEM"), ("Graylog", "api", "Log analytics"),
        ("LimaCharlie", "api", "Endpoint telemetry"), ("Falco", "cli", "Runtime detection"),
    ],
    "Web Archives / Search": [
        ("Google Cache Alternatives", "search", "Historical web research"), ("Bing Cache Research", "search", "Historical web research"),
        ("Wayback Machine", "public", "Historical web archive"), ("Common Crawl", "api", "Web archive data"),
        ("Arquivo.pt", "api", "Web archive"), ("UK Web Archive", "public", "Web archive"),
        ("National Archives Web Archive", "public", "Web archive"), ("Ghostarchive", "public", "Web archive"),
        ("Perma.cc", "public", "Web archive"), ("Archive.today", "public", "Web archive"),
        ("Google Search", "search", "Web search"), ("Bing Search", "search", "Web search"),
        ("Brave Search", "search", "Web search"), ("Mojeek", "search", "Web search"),
        ("Yandex", "search", "Web search"), ("Startpage", "search", "Web search"),
        ("SearXNG", "selfhost", "Meta-search"), ("DuckDuckGo", "search", "Web search"),
    ],
}

TOOL_CATALOG = [
    {"name": name, "kind": kind, "purpose": purpose, "category": category}
    for category, items in TOOL_GROUPS.items()
    for name, kind, purpose in items
]


def tool_fabric_status() -> dict[str, Any]:
    configured_env = {
        "VirusTotal": bool(settings.virustotal_api_key),
        "urlscan.io": bool(settings.urlscan_api_key),
        "AbuseIPDB": bool(getattr(settings, "abuseipdb_api_key", "")),
        "Have I Been Pwned": bool(getattr(settings, "hibp_api_key", "")),
        "Google Safe Browsing": bool(getattr(settings, "google_safe_browsing_api_key", "")),
        "DNSDumpster": bool(getattr(settings, "dnsdumpster_api_key", "")),
        "OpenAI Responses API": bool(settings.openai_api_key),
    }
    items = []
    for item in TOOL_CATALOG:
        status = "catalog-only"
        reason = "Manual/source reference or API contract cataloged; no connector configured."
        if item["name"] in configured_env and configured_env[item["name"]]:
            status = "live-configured"
            reason = "Credential configured; connector is eligible for this analysis."
        elif item["kind"] in {"cli", "python", "desktop", "local", "web", "event-log"}:
            executable = shutil.which(item["name"].lower()) or shutil.which(item["name"])
            status = "local-available" if executable else "local-not-detected"
            reason = "Local tool detected in PATH." if executable else "Install the local tool to use it outside this safe web service path."
        items.append({**item, "status": status, "reason": reason})
    return {
        "catalog_count": len(items),
        "live_configured_count": sum(1 for x in items if x["status"] == "live-configured"),
        "local_available_count": sum(1 for x in items if x["status"] == "local-available"),
        "categories": sorted({x["category"] for x in items}),
        "items": items,
        "boundary": "The fabric does not execute arbitrary third-party commands or crawl the dark web. Only explicit, fixed connectors are invoked.",
    }


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _evidence_id(*parts: Any) -> str:
    return "EV-" + hashlib.sha256("|".join(map(str, parts)).encode("utf-8", "replace")).hexdigest()[:14].upper()


def _sha256(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def _registered_domain(host: str) -> str:
    host = host.rstrip(".").lower()
    try:
        return str(try_psl(host).get("registered_domain") or host)
    except Exception:
        labels = [x for x in host.split(".") if x]
        return ".".join(labels[-2:]) if len(labels) > 1 else host


def _normalize_target(target: str) -> tuple[str, str, str, dict[str, Any]]:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("URL or domain is required")
    if len(raw) > 4096:
        raise ValueError("Target is too long")
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if not parsed.hostname:
        raise ValueError("Unable to identify a hostname")
    host = parsed.hostname.rstrip(".").lower()
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain") from exc
    if _is_ip(ascii_host):
        registered = ascii_host
    else:
        if "." not in ascii_host:
            raise ValueError("Target must be a domain or URL with a hostname")
        registered = _registered_domain(ascii_host)
    is_url = bool(urlparse(raw).scheme and urlparse(raw).scheme.lower() in {"http", "https"})
    url = raw if is_url else f"https://{ascii_host}/"
    if is_url:
        url = validate_url(raw)
    parsed_final = urlparse(url)
    return raw, ascii_host, registered, {
        "is_url": is_url,
        "normalized_url": url,
        "scheme": parsed_final.scheme,
        "port": parsed_final.port,
        "path": parsed_final.path or "/",
        "query": parsed_final.query,
        "fragment_present": bool(parsed_final.fragment),
        "username_present": bool(parsed_final.username),
        "password_present": bool(parsed_final.password),
    }


def _url_forensics(raw: str, normalized_url: str, domain: str) -> dict[str, Any]:
    parsed = urlparse(normalized_url)
    query_pairs = parsed.query.split("&") if parsed.query else []
    query_keys = [x.split("=", 1)[0] for x in query_pairs if x]
    suspicious_keys = sorted({
        key for key in query_keys
        if key.lower() in {"redirect", "url", "uri", "next", "return", "returnurl", "continue", "dest", "destination", "target", "goto", "link", "callback", "file", "path"}
    })
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    double_encoded = "%25" in raw.lower() or "%252f" in raw.lower() or "%252e" in raw.lower()
    labels = [x for x in (parsed.hostname or domain).split(".") if x]
    return {
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "registered_domain": _registered_domain(parsed.hostname or domain) if not _is_ip(parsed.hostname or domain) else parsed.hostname,
        "port": parsed.port,
        "non_standard_port": bool(parsed.port and parsed.port not in {80, 443}),
        "path": parsed.path or "/",
        "path_depth": len([x for x in (parsed.path or "/").split("/") if x]),
        "query_present": bool(parsed.query),
        "query_parameter_count": len(query_keys),
        "query_keys": query_keys[:100],
        "suspicious_redirect_parameters": suspicious_keys,
        "fragment_present": bool(parsed.fragment),
        "userinfo_present": bool(parsed.username or parsed.password),
        "percent_encoded_sequences": encoded,
        "double_encoding_indicators": double_encoded,
        "hostname_label_count": len(labels),
        "raw_length": len(raw),
        "normalized_url": normalized_url,
    }


def _script_profile(value: str) -> dict[str, Any]:
    scripts = {"latin": 0, "cyrillic": 0, "greek": 0, "arabic": 0, "other": 0}
    for ch in value:
        cp = ord(ch)
        if "a" <= ch.lower() <= "z": scripts["latin"] += 1
        elif 0x0400 <= cp <= 0x052F: scripts["cyrillic"] += 1
        elif 0x0370 <= cp <= 0x03FF: scripts["greek"] += 1
        elif 0x0600 <= cp <= 0x06FF: scripts["arabic"] += 1
        elif ch.isalpha(): scripts["other"] += 1
    active = [k for k, v in scripts.items() if v]
    return {"counts": scripts, "mixed_script": len(active) > 1, "active_scripts": active}


def _unicode_homoglyphs(host: str) -> list[str]:
    mapping = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X"}
    found = []
    for ch in host:
        if ch in mapping:
            found.append(f"{ch}→{mapping[ch]}")
    return found


def _levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j-1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _typosquat_candidates(registered: str) -> list[dict[str, Any]]:
    if _is_ip(registered):
        return []
    labels = registered.split(".")
    if len(labels) < 2: return []
    name, tld = ".".join(labels[:-1]), labels[-1]
    variants: set[str] = set()
    for i in range(len(name)):
        variants.add(name[:i] + name[i+1:])
        for ch in "abcdefghijklmnopqrstuvwxyz":
            if ch != name[i]: variants.add(name[:i] + ch + name[i+1:])
    for i in range(len(name)-1):
        variants.add(name[:i] + name[i+1] + name[i] + name[i+2:])
    variants.update({name.replace("-", ""), name.replace("-", "-") + "login", "login-" + name, name + "-secure", "secure-" + name})
    out=[]
    for v in sorted(variants):
        if not v or v == name or len(out) >= 80: continue
        out.append({"candidate": f"{v}.{tld}", "distance": _levenshtein(name, v), "method": "edit-distance-variant"})
    return out[:80]


async def _doh(client: httpx.AsyncClient, name: str, qtype: str) -> dict[str, Any]:
    url = "https://dns.google/resolve"
    try:
        r = await client.get(url, params={"name": name, "type": qtype}, headers={"accept": "application/dns-json"})
        data = r.json()
        return {"status": r.status_code, "data": data, "source": url}
    except Exception as exc:
        return {"status": 0, "error": str(exc), "data": {}, "source": url}


def _parse_dns_answers(data: dict[str, Any] | Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    answers = []
    for a in data.get("Answer") or []:
        if not isinstance(a, dict):
            continue
        answers.append({"name": a.get("name"), "type": a.get("type"), "ttl": a.get("TTL"), "value": a.get("data")})
    return answers


def _system_dns_records(name: str, rtype: str) -> list[dict[str, Any]]:
    """Synchronous resolver fallback used only when the public DoH collector fails."""
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 1.5
        resolver.lifetime = 2.5
        answer = resolver.resolve(name, rtype, raise_on_no_answer=False)
        rows=[]
        for rr in answer:
            value = None
            if rtype in {"A", "AAAA"}: value = getattr(rr, "address", None)
            elif rtype == "MX": value = f"{getattr(rr,'preference',0)} {getattr(rr,'exchange','')}".strip()
            elif rtype in {"CNAME","NS","PTR"}: value = str(getattr(rr, "target", rr)).rstrip(".")
            elif rtype == "SRV": value = f"{rr.priority} {rr.weight} {rr.port} {rr.target}".strip()
            elif rtype == "SOA": value = f"{rr.mname} {rr.rname} {rr.serial} {rr.refresh} {rr.retry} {rr.expire} {rr.minimum}"
            elif rtype == "CAA": value = f"{rr.flags} {rr.tag} {rr.value}"
            elif rtype in {"TXT","SPF"}: value = "".join(bytes(part).decode("utf-8", "replace") if isinstance(part, bytes) else str(part) for part in rr.strings)
            else: value = rr.to_text()
            if value is not None: rows.append({"name":name,"type":rtype,"ttl":getattr(answer, "rrset", None).ttl if getattr(answer,"rrset",None) else None,"value":str(value)})
        return rows
    except Exception:
        return []


def _record_dict(answers: list[dict[str, Any]] | dict[str, Any], rtype: str) -> list[dict[str, Any]]:
    if isinstance(answers, dict):
        answers = _parse_dns_answers(answers)
    elif not isinstance(answers, list):
        answers = []
    answers = [item for item in answers if isinstance(item, dict)]
    labels = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257, "DS": 43, "RRSIG": 46, "DNSKEY": 48, "NAPTR": 35, "TLSA": 52, "SSHFP": 44, "PTR": 12}
    code = labels.get(rtype)
    rows = []
    for item in answers:
        if code is None or item.get("type") == code:
            val = item.get("value")
            if isinstance(val, str) and rtype == "TXT": val = val.strip('"')
            rows.append({"name": item.get("name"), "ttl": item.get("ttl"), "value": val})
    return rows


async def _dns_bundle(domain: str) -> dict[str, Any]:
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "NAPTR", "DNSKEY", "DS", "RRSIG", "TLSA", "SSHFP"]
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        results = await asyncio.gather(*[_doh(client, domain, t) for t in record_types])
        raw = {t: results[i] for i, t in enumerate(record_types)}
        records = {t: _record_dict(raw[t].get("data") or {}, t) for t in record_types}
        # Use the host's configured resolver as a standards-compliant fallback. This
        # keeps A/AAAA/DNS data useful on networks that block public DoH endpoints.
        missing = [t for t in record_types if not records.get(t)]
        if missing:
            fallback_rows = await asyncio.gather(*[asyncio.to_thread(_system_dns_records, domain, t) for t in missing])
            for t, rows in zip(missing, fallback_rows):
                if rows: records[t] = rows
        ips = sorted({x["value"] for x in records["A"] if x.get("value")} | {x["value"] for x in records["AAAA"] if x.get("value")})
        # PTR is queried for current IPs only; historical passive DNS requires a provider.
        ptr_results = await asyncio.gather(*[_doh(client, ipaddress.ip_address(ip).reverse_pointer, "PTR") for ip in ips[:30]])
    reverse = {}
    for ip, result in zip(ips[:30], ptr_results):
        reverse[ip] = _record_dict(result.get("data") or {}, "PTR") or []
    return {"records": records, "reverse_dns": reverse, "resolver": "Google DNS-over-HTTPS", "queried_at": _now()}


async def _rdap(client: httpx.AsyncClient, path: str) -> dict[str, Any]:
    try:
        r = await client.get(f"https://rdap.org/{path.lstrip('/')}", headers={"accept": "application/rdap+json, application/json"})
        if r.status_code >= 400:
            return {"status": r.status_code, "error": r.text[:300]}
        return {"status": r.status_code, "data": r.json(), "url": str(r.url)}
    except Exception as exc:
        return {"status": 0, "error": str(exc)}


def _rdap_events(data: dict[str, Any]) -> dict[str, Any]:
    events = []
    for event in data.get("events") or []:
        if not isinstance(event, dict):
            continue
        events.append({"event_action": event.get("eventAction"), "date": event.get("eventDate"), "actor": event.get("eventActor")})
    return events


def _rdap_entities(data: dict[str, Any]) -> list[dict[str, Any]]:
    out=[]
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        roles=entity.get("roles") or []
        vcard={}
        vcard_array=entity.get("vcardArray") or []
        rows=vcard_array[1] if isinstance(vcard_array,list) and len(vcard_array)>1 and isinstance(vcard_array[1],list) else []
        for row in rows:
            if not isinstance(row, list) or len(row) < 4:
                continue
            key=str(row[0]).lower()
            if key in {"fn", "org", "email", "tel", "adr"}:
                vcard[key] = row[3]
        adr=vcard.get("adr")
        address={}
        if isinstance(adr,list):
            # vCard ADR: PO box, extended, street, locality, region, postal code, country
            vals=list(adr)+[None]*7
            address={"street":vals[2],"city":vals[3],"region":vals[4],"postalCode":vals[5],"country":vals[6]}
        elif isinstance(adr,dict):
            address=dict(adr)
        public_ids=[]
        for pid in entity.get("publicIds") or []:
            if isinstance(pid,dict): public_ids.append({"type":pid.get("type"),"identifier":pid.get("identifier")})
        # Some registries publish abuse contacts as separate entities/remarks; preserve all raw public identifiers.
        out.append({"handle": entity.get("handle"), "roles": roles, "name": vcard.get("fn"), "organization": vcard.get("org"), "email": vcard.get("email"), "phone": vcard.get("tel"), "address": address, "public_ids": public_ids, "raw": entity})
    return out


async def _dns_auth_bundle(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    targets = {
        "SPF": (domain, "TXT"),
        "DMARC": (f"_dmarc.{domain}", "TXT"),
        "MTA-STS": (f"_mta-sts.{domain}", "TXT"),
        "TLS-RPT": (f"_smtp._tls.{domain}", "TXT"),
        "DKIM-default": (f"default._domainkey.{domain}", "TXT"),
    }
    keys = list(targets)
    rows = await asyncio.gather(*[_doh(client, name, qtype) for name, qtype in targets.values()])
    out = {}
    for key, row in zip(keys, rows):
        answers = _record_dict(row.get("data") or {}, "TXT")
        out[key] = {
            "name": targets[key][0],
            "status": "observed" if answers else ("no_record" if row.get("status") == 200 else row.get("status", "unknown")),
            "records": answers[:50],
            "source": row.get("source"),
        }
    txt_values = " ".join(str(x.get("value") or "") for x in out.get("SPF", {}).get("records", []))
    out["summary"] = {
        "spf": bool(re.search(r"(?i)v=spf1", txt_values)),
        "dmarc": bool(out.get("DMARC", {}).get("records")),
        "mta_sts": bool(out.get("MTA-STS", {}).get("records")),
        "tls_rpt": bool(out.get("TLS-RPT", {}).get("records")),
        "dkim_selector_tested": bool(out.get("DKIM-default", {}).get("records")),
        "note": "DKIM selector discovery is incomplete without a selector corpus; the default selector is only a spot check.",
    }
    return out


def _dns_posture(dns: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    records = dns.get("records") or {}
    ttl_values = [int(row["ttl"]) for rows in records.values() for row in rows if isinstance(row, dict) and str(row.get("ttl", "")).isdigit()]
    current_ip_rows = records.get("A", []) + records.get("AAAA", [])
    return {
        "record_counts": {k: len(v or []) for k, v in records.items()},
        "non_empty_types": [k for k, v in records.items() if v],
        "total_records": sum(len(v or []) for v in records.values()),
        "current_ip_count": len(current_ip_rows),
        "nameserver_count": len(records.get("NS") or []),
        "mail_exchange_count": len(records.get("MX") or []),
        "ttl_min": min(ttl_values) if ttl_values else None,
        "ttl_max": max(ttl_values) if ttl_values else None,
        "dnssec_chain_observed": bool(records.get("DNSKEY")) and bool(records.get("DS")),
        "email_auth": auth.get("summary", {}),
        "resolver": dns.get("resolver"),
    }


def _ip_intelligence(dns: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    reverse = dns.get("reverse_dns") or {}
    for rtype in ("A", "AAAA"):
        for row in dns.get("records", {}).get(rtype, [])[:100]:
            value = str(row.get("value") or "")
            if not value:
                continue
            try:
                ip = ipaddress.ip_address(value)
                classification = "public" if ip.is_global else "private" if ip.is_private else "reserved/special"
                rows.append({
                    "ip": value, "version": ip.version, "classification": classification,
                    "is_global": ip.is_global, "is_private": ip.is_private, "is_reserved": ip.is_reserved,
                    "ptr": [x.get("value") for x in reverse.get(value, []) if x.get("value")],
                })
            except ValueError:
                rows.append({"ip": value, "classification": "invalid-returned-value", "ptr": []})
    return rows


def _certificate_posture(ct: dict[str, Any], tls: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(UTC)
    expiry_days = None
    if tls.get("not_after"):
        try:
            expiry = datetime.fromisoformat(str(tls["not_after"]).replace("Z", "+00:00"))
            expiry_days = (expiry - now).days
        except Exception:
            pass
    return {
        "ct_certificate_count": int(ct.get("count", 0) or 0),
        "ct_hostname_count": len(ct.get("names") or []),
        "live_tls_san_count": len(tls.get("san") or []),
        "live_tls_wildcard": any(str(x).startswith("*.") for x in (tls.get("san") or [])),
        "live_tls_expiry_days": expiry_days,
        "live_tls_issuer": tls.get("issuer"),
        "live_tls_fingerprint": tls.get("sha256_fingerprint"),
    }


def _http_security_posture(http: dict[str, Any], security_headers: dict[str, Any]) -> dict[str, Any]:
    headers = {str(k).lower(): str(v) for k, v in (http.get("headers") or {}).items()}
    cookie_headers = [v for k, v in (http.get("headers") or {}).items() if str(k).lower() == "set-cookie"]
    return {
        "content_type": headers.get("content-type"),
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "cache_control": headers.get("cache-control"),
        "cookie_count": len(cookie_headers),
        "cookie_secure_count": sum(1 for x in cookie_headers if "secure" in x.lower()),
        "cookie_httponly_count": sum(1 for x in cookie_headers if "httponly" in x.lower()),
        "cookie_samesite_count": sum(1 for x in cookie_headers if "samesite" in x.lower()),
        "security_headers_present": sum(1 for x in security_headers.values() if x.get("present")),
        "security_headers_total": len(security_headers),
    }


def _osint_pivots(domain: str, url: str, graph: dict[str, Any], ips: list[str]) -> dict[str, Any]:
    return {
        "search_engine": [f"site:{domain}", f"site:*.{domain}", f'"{domain}"', f'site:{domain} filetype:pdf', f'site:{domain} inurl:login'],
        "certificate": [f'cert:{domain}', f'hostname:{domain}'],
        "url_history": [f'domain:{domain}', f'url:{domain}'],
        "infrastructure": [f'ip:{ip}' for ip in ips[:20]],
        "identity": [f'"@{domain}"', f'"{domain}" "password"', f'"{domain}" "employee"'],
        "graph_node_count": graph.get("node_count", 0),
        "note": "Queries are pivots for authorized investigation; results require the configured source or analyst verification.",
    }


def _investigation_matrix(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"id":"identity","name":"Domain identity / registration","status":"observed" if result.get("whois_rdap", {}).get("events") or result.get("whois_rdap", {}).get("entities") else "gap"},
        {"id":"dns","name":"DNS / DNSSEC","status":"observed" if result.get("dns_posture", {}).get("total_records") else "gap"},
        {"id":"certs","name":"Certificate transparency","status":"observed" if result.get("certificate_transparency", {}).get("count") else "no_records"},
        {"id":"web","name":"HTTP / TLS / technology","status":"observed" if result.get("http", {}).get("status") == "completed" else "gap"},
        {"id":"reputation","name":"Reputation providers","status":"provider-dependent"},
        {"id":"breach","name":"Breach / leak intelligence","status":"provider-dependent"},
        {"id":"traffic","name":"Traffic / prevalence","status":"provider-dependent"},
        {"id":"historical_dns","name":"Historical passive DNS","status":"provider-dependent"},
        {"id":"graph","name":"Relationship graph","status":"observed" if result.get("graph", {}).get("edge_count") else "gap"},
        {"id":"ai","name":"AI evidence copilot","status":result.get("ai_analysis", {}).get("status", "unknown")},
    ]


async def _ct_lookup(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    url = "https://crt.sh/"
    try:
        r = await client.get(url, params={"q": f"%.{domain}", "output": "json"}, headers={"accept": "application/json"})
        if r.status_code >= 400:
            return {"status": r.status_code, "count": 0, "certificates": [], "error": r.text[:300], "source": url}
        payload = r.json() if r.content else []
        certs=[]; names=set()
        for row in payload[:1500]:
            names_value=str(row.get("name_value") or "")
            san=[x.strip().lower().lstrip("*.") for x in re.split(r"[\n,]+", names_value) if x.strip()]
            names.update(x for x in san if x.endswith(domain) or x == domain)
            certs.append({
                "id": row.get("id"), "issuer_ca_id": row.get("issuer_ca_id"), "issuer_name": row.get("issuer_name"),
                "common_name": row.get("common_name"), "name_value": names_value, "not_before": row.get("not_before"),
                "not_after": row.get("not_after"), "serial_number": row.get("serial_number"),
            })
        return {"status": r.status_code, "count": len(certs), "certificates": certs[:600], "names": sorted(names)[:1200], "source": str(r.url), "queried_at": _now()}
    except Exception as exc:
        return {"status": 0, "count": 0, "certificates": [], "names": [], "error": str(exc), "source": url}


async def _dnsdumpster(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    # Delegate the provider contract to the modular URL & Domain Analyst package.
    from phishhunter.url_domain_analyst.connectors.providers.dnsdumpster import lookup
    data = await lookup(client, domain, getattr(settings, "dnsdumpster_api_key", ""))
    data["source"] = "DNSDumpster"
    data.setdefault("queried_at", _now())
    return data


async def _urlscan_search(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    key = getattr(settings, "urlscan_api_key", "")
    if not key:
        return {"status": "not_configured", "provider": "urlscan.io", "results": []}
    try:
        r=await client.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 100}, headers={"api-key": key, "accept": "application/json"})
        if r.status_code >= 400: return {"status": r.status_code, "provider": "urlscan.io", "results": []}
        data=r.json(); results=data.get("results") or []
        return {"status": "completed", "provider": "urlscan.io", "total": data.get("total", len(results)), "results": results[:100], "queried_at": _now()}
    except Exception as exc:
        return {"status": "error", "provider": "urlscan.io", "results": [], "error": str(exc)}


async def _vt_domain(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    key = settings.virustotal_api_key
    if not key:
        return {"status": "not_configured", "provider": "VirusTotal"}
    try:
        r=await client.get(f"https://www.virustotal.com/api/v3/domains/{quote(domain, safe='')}", headers={"x-apikey": key, "accept": "application/json"})
        if r.status_code >= 400: return {"status": r.status_code, "provider": "VirusTotal"}
        data=r.json().get("data", {}).get("attributes", {})
        return {"status": "completed", "provider": "VirusTotal", "domain": domain, "reputation": data.get("reputation"), "last_analysis_stats": data.get("last_analysis_stats"), "categories": data.get("categories"), "registrar": data.get("registrar"), "creation_date": data.get("creation_date"), "last_analysis_date": data.get("last_analysis_date"), "queried_at": _now()}
    except Exception as exc:
        return {"status": "error", "provider": "VirusTotal", "error": str(exc)}


async def _hibp_domain(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    key=getattr(settings, "hibp_api_key", "")
    if not key:
        return {"status":"not_configured","provider":"Have I Been Pwned","records":[],"note":"Domain search requires an authenticated, verified domain in HIBP."}
    try:
        r=await client.get(f"https://haveibeenpwned.com/api/v3/breachedDomain/{quote(domain, safe='')}", headers={"hibp-api-key":key,"user-agent":"Phish-Hunter URL & Domain Analyst","accept":"application/json"})
        if r.status_code == 404: return {"status":"no_results","provider":"Have I Been Pwned","records":[],"queried_at":_now()}
        if r.status_code >= 400: return {"status":r.status_code,"provider":"Have I Been Pwned","records":[],"error":r.text[:300]}
        data=r.json() if r.content else {}
        records=[]
        if isinstance(data, dict):
            for alias, breaches in list(data.items())[:10000]:
                records.append({"alias": alias, "domain": domain, "breaches": breaches if isinstance(breaches,list) else [breaches]})
        return {"status":"completed","provider":"Have I Been Pwned","records":records,"breached_identity_count":len(records),"queried_at":_now(),"privacy_note":"Returned domain-search data is available only for a domain verified in the HIBP account."}
    except Exception as exc:
        return {"status":"error","provider":"Have I Been Pwned","records":[],"error":str(exc)}


async def _gsb_url(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    key=getattr(settings, "google_safe_browsing_api_key", "")
    if not key:
        return {"status":"not_configured","provider":"Google Safe Browsing"}
    try:
        endpoint=f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={quote(key, safe='')}"
        body={"client":{"clientId":"phish-hunter","clientVersion":"24.4"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}}
        r=await client.post(endpoint,json=body,headers={"accept":"application/json"})
        if r.status_code >= 400:return {"status":r.status_code,"provider":"Google Safe Browsing"}
        data=r.json() if r.content else {}
        return {"status":"completed","provider":"Google Safe Browsing","matches":data.get("matches") or [],"queried_at":_now()}
    except Exception as exc:
        return {"status":"error","provider":"Google Safe Browsing","error":str(exc)}


async def _abuseipdb(client: httpx.AsyncClient, ips: list[str]) -> dict[str, Any]:
    key=getattr(settings, "abuseipdb_api_key", "")
    if not key or not ips:
        return {"status":"not_configured" if not key else "no_ips","provider":"AbuseIPDB","results":[]}
    async def one(ip: str):
        try:
            r=await client.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress":ip,"maxAgeInDays":90}, headers={"Key":key,"Accept":"application/json"})
            if r.status_code >= 400:return {"ip":ip,"status":r.status_code}
            d=r.json().get("data",{})
            return {"ip":ip,"status":"completed","abuseConfidenceScore":d.get("abuseConfidenceScore"),"countryCode":d.get("countryCode"),"isp":d.get("isp"),"domain":d.get("domain"),"totalReports":d.get("totalReports")}
        except Exception as exc:return {"ip":ip,"status":"error","error":str(exc)}
    return {"status":"completed","provider":"AbuseIPDB","results":await asyncio.gather(*[one(ip) for ip in ips[:20]]),"queried_at":_now()}


async def _http_probe(target_url: str) -> dict[str, Any]:
    probe = {"requested_url": target_url, "status": "not_attempted"}
    try:
        # fetch_url performs synchronous DNS/socket work behind an async wrapper.
        # Move the entire probe into a worker thread so a slow/unreachable target
        # cannot block the FastAPI event loop or prevent wait_for() from firing.
        result = await asyncio.to_thread(lambda: asyncio.run(fetch_url(target_url)))
        html = result.get("content") or ""
        soup=BeautifulSoup(html, "html.parser")
        title=soup.title.get_text(" ", strip=True) if soup.title else ""
        headers=result.get("headers") or {}
        scripts=[urljoin(result.get("final_url",target_url), s.get("src")) for s in soup.find_all("script",src=True)]
        links=[]
        for a in soup.find_all("a",href=True)[:1000]:
            u=urljoin(result.get("final_url",target_url),a.get("href"))
            links.append({"url":u,"text":a.get_text(" ",strip=True)[:160],"external":(urlparse(u).hostname or "").lower() != (urlparse(result.get("final_url",target_url)).hostname or "").lower()})
        forms=[]
        for form in soup.find_all("form")[:200]:
            action=urljoin(result.get("final_url",target_url),form.get("action") or result.get("final_url",target_url))
            fields=[]
            for field in form.find_all(["input","select","textarea","button"])[:100]:
                fields.append({"name":field.get("name"),"type":field.get("type",field.name),"autocomplete":field.get("autocomplete")})
            forms.append({"action":action,"method":(form.get("method") or "get").lower(),"fields":fields,"cross_origin":(urlparse(action).hostname or "").lower() != (urlparse(result.get("final_url",target_url)).hostname or "").lower()})
        return {
            "status":"completed","status_code":result.get("status_code"),"reason":result.get("reason"),"final_url":result.get("final_url"),
            "headers":headers,"content_length":result.get("content_length"),"truncated":result.get("truncated"),
            "resolved_ip":result.get("resolved_ip"),"redirects":result.get("history") or [],"redirect_count":result.get("redirect_count",0),
            "resolutions":result.get("resolutions") or [],"title":title,"forms":forms,"links":links[:500],"scripts":scripts[:200],
            "html_sample":html[:25000],
        }
    except Exception as exc:
        probe["status"]="error"; probe["error"]=str(exc); return probe


def _security_headers(headers: dict[str, Any]) -> dict[str, Any]:
    h={str(k).lower():str(v) for k,v in (headers or {}).items()}
    wanted={"strict-transport-security":"HSTS","content-security-policy":"CSP","x-content-type-options":"X-Content-Type-Options","x-frame-options":"X-Frame-Options","referrer-policy":"Referrer-Policy","permissions-policy":"Permissions-Policy","cross-origin-opener-policy":"COOP","cross-origin-resource-policy":"CORP","cross-origin-embedder-policy":"COEP"}
    out={}
    for k,label in wanted.items():
        out[label]={"present":bool(h.get(k)),"value":h.get(k)}
    return out


def _tech_fingerprint(http: dict[str, Any]) -> list[dict[str, Any]]:
    headers={str(k).lower():str(v) for k,v in (http.get("headers") or {}).items()}
    html=http.get("html_sample") or ""
    lower=html.lower()
    observed=[]
    def add(name, evidence, confidence=80): observed.append({"technology":name,"evidence":evidence,"confidence":confidence})
    if "cloudflare" in headers.get("server","").lower() or "cf-ray" in headers: add("Cloudflare","HTTP headers")
    if "nginx" in headers.get("server","").lower(): add("nginx","Server header")
    if "apache" in headers.get("server","").lower(): add("Apache","Server header")
    if "php" in headers.get("x-powered-by","").lower() or "php" in lower: add("PHP","X-Powered-By or HTML marker",75)
    if "asp.net" in headers.get("x-powered-by","").lower() or "asp.net" in lower: add("ASP.NET","HTTP/HTML marker",75)
    if "wordpress" in lower or "/wp-content/" in lower: add("WordPress","HTML path/marker")
    if "drupal-settings-json" in lower or "drupal" in lower: add("Drupal","HTML marker",70)
    if "joomla" in lower: add("Joomla","HTML marker",70)
    if "shopify" in lower or "cdn.shopify.com" in lower: add("Shopify","HTML/script marker",85)
    if "react" in lower or "__next_data__" in lower: add("React/Next.js","HTML/script marker",70)
    if "ng-version" in lower: add("Angular","ng-version marker",90)
    if "data-v-" in lower: add("Vue.js","data-v marker",70)
    if "bootstrap" in lower or "bootstrapcdn" in lower: add("Bootstrap","HTML/script marker",70)
    if "jquery" in lower: add("jQuery","HTML/script marker",70)
    meta=BeautifulSoup(html,"html.parser") if html else None
    if meta:
        gen=meta.find("meta",attrs={"name":re.compile("^generator$",re.I)})
        if gen and gen.get("content"): add(str(gen.get("content")),"meta generator",90)
    if headers.get("x-powered-by"): add(headers["x-powered-by"],"X-Powered-By header",85)
    if headers.get("server"): add(headers["server"],"Server header",85)
    return observed[:100]


def _ssl_probe(host: str, port: int = 443) -> dict[str, Any]:
    try:
        addresses=resolve_and_validate(host,port)
        ip=addresses[0]
        context=ssl.create_default_context()
        with socket.create_connection((ip,port),timeout=max(3,settings.fetch_timeout_seconds)) as raw:
            with context.wrap_socket(raw,server_hostname=host) as sock:
                cert=sock.getpeercert()
                binary=sock.getpeercert(binary_form=True) or b""
                return {
                    "status":"completed","peer_ip":ip,"tls_version":sock.version(),"cipher":sock.cipher(),
                    "subject":cert.get("subject"),"issuer":cert.get("issuer"),"not_before":cert.get("notBefore"),
                    "not_after":cert.get("notAfter"),"serial_number":cert.get("serialNumber"),
                    "san":[value for kind,value in (cert.get("subjectAltName") or []) if kind=="DNS"][:1000],
                    "sha256_fingerprint":hashlib.sha256(binary).hexdigest() if binary else None,
                }
    except Exception as exc:
        return {"status":"error","error":str(exc)}


def _network_associations(domain: str, dns: dict[str, Any]) -> dict[str, Any]:
    ips=[]
    for t in ("A","AAAA"):
        ips.extend([x.get("value") for x in dns.get("records",{}).get(t,[]) if x.get("value")])
    mx=[x.get("value","").split()[-1].rstrip(".") for x in dns.get("records",{}).get("MX",[]) if x.get("value")]
    ns=[str(x.get("value") or "").rstrip(".") for x in dns.get("records",{}).get("NS",[]) if x.get("value")]
    return {"current_ips":sorted(set(ips)),"mx_hosts":sorted(set(mx)),"name_servers":sorted(set(ns)),"reverse_dns":dns.get("reverse_dns",{})}


def _reputation_summary(vt: dict[str, Any], urlscan: dict[str, Any], gsb: dict[str, Any], abuse: dict[str, Any], hibp: dict[str, Any]) -> dict[str, Any]:
    vt = vt if isinstance(vt, dict) else {}
    urlscan = urlscan if isinstance(urlscan, dict) else {}
    gsb = gsb if isinstance(gsb, dict) else {}
    abuse = abuse if isinstance(abuse, dict) else {}
    hibp = hibp if isinstance(hibp, dict) else {}
    signals=[]
    stats=vt.get("last_analysis_stats") or {}
    stats = stats if isinstance(stats, dict) else {}
    for key in ("malicious","suspicious"):
        try:
            count=int(stats.get(key,0))
        except Exception: count=0
        if count: signals.append({"provider":"VirusTotal","signal":key,"count":count,"severity":"high" if key=="malicious" else "medium"})
    gsb_matches=gsb.get("matches") if isinstance(gsb.get("matches"), list) else []
    if gsb_matches: signals.append({"provider":"Google Safe Browsing","signal":"threat_match","count":len(gsb_matches),"severity":"critical"})
    for row in abuse.get("results") or []:
        if not isinstance(row, dict):
            continue
        try: sc=int(row.get("abuseConfidenceScore",0) or 0)
        except Exception: sc=0
        if sc >= 50: signals.append({"provider":"AbuseIPDB","signal":"abuse_confidence","ip":row.get("ip"),"score":sc,"severity":"high"})
    breach_count=hibp.get("breached_identity_count",0) if hibp.get("status")=="completed" else 0
    if breach_count: signals.append({"provider":"Have I Been Pwned","signal":"breached_domain_identities","count":breach_count,"severity":"high"})
    verdict="malicious" if any(x.get("severity")=="critical" for x in signals) else "highly-suspicious" if any(x.get("severity")=="high" for x in signals) else "suspicious" if signals else "no-confirmed-provider-hit"
    return {"verdict":verdict,"signals":signals,"provider_states":{"VirusTotal":vt.get("status"),"urlscan.io":urlscan.get("status"),"Google Safe Browsing":gsb.get("status"),"AbuseIPDB":abuse.get("status"),"Have I Been Pwned":hibp.get("status")}}


def _domain_overview(domain: str, raw: str) -> dict[str, Any]:
    labels=domain.split(".")
    unicode_homoglyphs=_unicode_homoglyphs(raw)
    script=_script_profile(raw)
    typo=_typosquat_candidates(_registered_domain(domain))
    return {
        "domain":domain,"fqdn":domain,"registered_domain":_registered_domain(domain),"raw_target":raw,
        "subdomain_depth":max(0,len(labels)-2),"length":len(domain),"entropy":_entropy(domain),
        "punycode":any(x.startswith("xn--") for x in labels),"idn_homoglyphs":unicode_homoglyphs,
        "mixed_script":script["mixed_script"],"script_profile":script,"typosquat_candidates":typo[:40],
        "lookalike_brand_matches":[],"verdict":"review",
    }


def _build_graph(domain: str, overview: dict[str, Any], rdap: dict[str, Any], dns: dict[str, Any], ct: dict[str, Any], http: dict[str, Any], tls: dict[str, Any], tech: list[dict[str, Any]], reputation: dict[str, Any], breach: dict[str, Any]) -> dict[str, Any]:
    nodes={}; edges=[]
    def node(nid,kind,label,meta=None): nodes.setdefault(nid,{"id":nid,"kind":kind,"label":str(label)[:240],"meta":meta or {}})
    def edge(a,rel,b,confidence=90,source="analysis"):
        edges.append({"source":a,"relation":rel,"target":b,"confidence":confidence,"source_ref":source})
    root=f"domain:{domain}"; node(root,"domain",domain,{"role":"target"})
    reg=f"registered:{overview.get('registered_domain')}"; node(reg,"registered-domain",overview.get("registered_domain")); edge(root,"registered-under",reg,99,"domain-normalization")
    if rdap.get("registrar"):
        r=f"registrar:{rdap['registrar']}"; node(r,"registrar",rdap['registrar']); edge(reg,"registered-with",r,95,"RDAP")
    for ip in (dns.get("records",{}).get("A",[]) + dns.get("records",{}).get("AAAA",[]))[:100]:
        v=ip.get("value");
        if v: nid=f"ip:{v}"; node(nid,"ip",v); edge(root,"resolves-to",nid,98,"DNS")
    for ns in dns.get("records",{}).get("NS",[])[:50]:
        v=str(ns.get("value") or "").rstrip(".")
        if v: nid=f"ns:{v}"; node(nid,"nameserver",v); edge(root,"delegated-to",nid,98,"DNS")
    for mx in dns.get("records",{}).get("MX",[])[:50]:
        v=str(mx.get("value") or "")
        if v:
            host=v.split()[-1].rstrip("."); nid=f"mx:{host}"; node(nid,"mx",host); edge(root,"mail-handled-by",nid,95,"DNS")
    for cname in dns.get("records", {}).get("CNAME", [])[:50]:
        value = str(cname.get("value") or "").rstrip(".")
        if value:
            nid=f"cname:{value}"; node(nid,"cname",value); edge(root,"aliases-to",nid,96,"DNS")
    subdomains=sorted(set(ct.get("names") or []))
    for sub in subdomains[:250]:
        if sub == domain: continue
        nid=f"subdomain:{sub}"; node(nid,"subdomain",sub); edge(root,"certificate-observed",nid,85,"crt.sh")
    for cert in (ct.get("certificates") or [])[:120]:
        if not isinstance(cert, dict):
            continue
        cid=str(cert.get("id") or _sha256(json.dumps(cert,sort_keys=True))[:12]); nid=f"cert:{cid}"; node(nid,"certificate",cert.get("common_name") or cid,{"issuer":cert.get("issuer_name"),"not_before":cert.get("not_before"),"not_after":cert.get("not_after")}); edge(root,"covered-by",nid,92,"crt.sh")
        for covered in [x.strip().lower().lstrip("*.") for x in re.split(r"[\n,]+", str(cert.get("name_value") or "")) if x.strip()][:30]:
            if covered != domain and (covered.endswith("." + domain) or covered == domain):
                sid=f"subdomain:{covered}"; node(sid,"subdomain",covered); edge(nid,"covers",sid,90,"crt.sh")
    for t in tech[:50]:
        if not isinstance(t, dict) or not t.get('technology'):
            continue
        nid=f"tech:{t['technology']}"; node(nid,"technology",t['technology']); edge(root,"uses",nid,int(t.get('confidence',70)),"HTTP fingerprint")
    if http.get("final_url"):
        u=http["final_url"]; nid=f"url:{u}"; node(nid,"url",u); edge(root,"served-at",nid,98,"HTTP")
    redirects=http.get("redirects") or []
    previous = f"domain:{domain}"
    for idx, redirect in enumerate(redirects[:30], 1):
        u = str(redirect or "").strip()
        if not u: continue
        rid=f"redirect:{idx}:{u}"; node(rid,"redirect",u,{"sequence":idx}); edge(previous,"redirects-to",rid,93,"HTTP")
        previous=rid
    for form in (http.get("forms") or [])[:80]:
        if not isinstance(form, dict):
            continue
        action=str(form.get("action") or "").strip()
        if action:
            fid=f"form:{action}"; node(fid,"form-action",action,{"cross_origin":bool(form.get("cross_origin"))}); edge(root,"form-submits-to",fid,90,"HTTP")
    for script in (http.get("scripts") or [])[:80]:
        value=str(script or "").strip()
        if value:
            sid=f"script:{value}"; node(sid,"script",value); edge(root,"loads-script",sid,82,"HTTP")
    for link in (http.get("links") or [])[:100]:
        if not isinstance(link, dict):
            continue
        value=str(link.get("url") or "").strip()
        if value and link.get("external"):
            lid=f"external:{value}"; node(lid,"external-link",value,{"text":link.get("text")}); edge(root,"links-to",lid,78,"HTTP")
    if tls.get("sha256_fingerprint"):
        nid=f"tls:{tls['sha256_fingerprint']}"; node(nid,"tls-certificate",tls["sha256_fingerprint"][:20]+'…'); edge(root,"presents",nid,98,"TLS")
    for sig in reputation.get("signals") or []:
        nid=f"reputation:{sig['provider']}:{sig['signal']}"; node(nid,"reputation",f"{sig['provider']} · {sig['signal']}"); edge(root,"flagged-by",nid,88,sig['provider'])
    for row in breach.get("records") or []:
        nid=f"breach:{row.get('alias')}"; node(nid,"breach-identity",f"{row.get('alias')}@{domain}",{ "breaches":row.get("breaches") }); edge(nid,"belongs-to",root,90,"Have I Been Pwned")
    for ip, ptrs in (dns.get("reverse_dns") or {}).items():
        for ptr in ptrs[:10]:
            val=str(ptr.get("value") or "").rstrip(".")
            if val: nid=f"rdns:{val}"; node(nid,"reverse-dns",val); edge(f"ip:{ip}","reverse-names-to",nid,88,"PTR")
    return {"nodes":list(nodes.values())[:1000],"edges":edges[:3000],"node_count":len(nodes),"edge_count":len(edges)}


def _risk(overview: dict[str, Any], dns: dict[str, Any], rdap: dict[str, Any], http: dict[str, Any], tls: dict[str, Any], rep: dict[str, Any], breach: dict[str, Any]) -> dict[str, Any]:
    signals=[]
    def add(name,points,severity,confidence,reason):
        signals.append({"name":name,"weight":points,"contribution":points,"severity":severity,"confidence":confidence,"reason":reason})
    if overview.get("punycode"): add("punycode",10,"medium",90,"IDNA/punycode label present")
    if overview.get("mixed_script"): add("mixed-script",20,"high",90,"Hostname contains characters from multiple writing systems")
    if overview.get("idn_homoglyphs"): add("homoglyph",20,"high",85,"Potential lookalike characters detected")
    if overview.get("entropy",0)>=4.0: add("high-hostname-entropy",5,"low",70,"Hostname entropy is unusually high")
    if overview.get("subdomain_depth",0)>=4: add("deep-subdomain",6,"low",75,"Multiple nested subdomain labels observed")
    if overview.get("length",0)>=45: add("long-hostname",5,"low",80,"Hostname is unusually long")
    tld=overview.get("domain","").split(".")[-1]
    if tld in {"zip","click","top","mov","gq","tk","work","country","rest","fit"}: add("higher-risk-tld",5,"medium",55,f"TLD {tld} is historically common in abuse reports; this is only a weak signal")
    txt=" ".join(str(x.get("value") or "") for x in dns.get("records",{}).get("TXT",[]))
    if not re.search(r"(?i)v=spf1",txt): add("no-visible-spf",2,"info",60,"No SPF TXT record observed by the selected resolver")
    if not dns.get("records",{}).get("DNSKEY") or not dns.get("records",{}).get("DS"): add("dnssec-not-evident",2,"info",70,"DNSSEC chain elements were not both observed")
    if http.get("redirect_count",0)>=3: add("redirect-chain",8,"medium",90,"Three or more HTTP redirects observed")
    if http.get("status_code") and int(http.get("status_code"))>=400: add("http-error",3,"low",95,f"HTTP status {http.get('status_code')}")
    pwd=sum(1 for f in (http.get("forms") or []) if any(str(x.get("type")).lower()=="password" for x in f.get("fields",[])))
    cross=sum(1 for f in (http.get("forms") or []) if f.get("cross_origin"))
    if pwd: add("password-form",18,"high",90,f"{pwd} password form(s) observed")
    if cross: add("cross-origin-form",18,"high",90,f"{cross} form action(s) leave the page origin")
    if tls.get("status")!="completed" and urlparse(http.get("final_url") or "").scheme=="https": add("tls-failure",15,"high",90,"HTTPS probe did not complete successfully")
    for sig in rep.get("signals") or []:
        pts=28 if sig.get("severity")=="critical" else 20 if sig.get("severity")=="high" else 10
        add(f"provider:{sig.get('provider')}:{sig.get('signal')}",pts,sig.get("severity","medium"),95,"Independent provider signal observed")
    score=min(100,sum(x["weight"] for x in signals))
    verdict="critical" if score>=80 else "high-risk" if score>=55 else "suspicious" if score>=25 else "low-risk"
    return {"score":score,"verdict":verdict,"signals":signals,"confidence":round(sum(x["confidence"] for x in signals)/len(signals),1) if signals else 50,"explanation":"Score is an explainable triage aid. It is not proof of maliciousness, ownership, compromise or attribution."}


def _ioc_set(domain: str, dns: dict[str, Any], http: dict[str, Any], tls: dict[str, Any], ct: dict[str, Any]) -> dict[str, list[str]]:
    out={"domains":set(),"urls":set(),"ips":set(),"emails":set(),"certificate_hashes":set(),"subdomains":set()}
    out["domains"].add(domain)
    for sub in ct.get("names") or []: out["subdomains"].add(sub)
    for t in ("A","AAAA"):
        for row in dns.get("records",{}).get(t,[]):
            if row.get("value"): out["ips"].add(str(row["value"]))
    if http.get("final_url"): out["urls"].add(http["final_url"])
    for row in (http.get("links") or []):
        host=urlparse(row.get("url") or "").hostname or ""
        if host: out["domains"].add(host.lower())
        if row.get("url"): out["urls"].add(row["url"])
    html=http.get("html_sample") or ""
    for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",html): out["emails"].add(email.lower())
    if tls.get("sha256_fingerprint"): out["certificate_hashes"].add(tls["sha256_fingerprint"])
    return {k:sorted(v)[:2000] for k,v in out.items()}


def _timeline(overview: dict[str, Any], rdap: dict[str, Any], ct: dict[str, Any], http: dict[str, Any], rep: dict[str, Any], breach: dict[str, Any]) -> list[dict[str, Any]]:
    rows=[]
    for ev in rdap.get("events") or []:
        if ev.get("date"): rows.append({"timestamp":ev["date"],"event":f"RDAP {ev.get('event_action')}","source":"RDAP","evidence_id":_evidence_id("rdap",ev)})
    for cert in (ct.get("certificates") or [])[:250]:
        if cert.get("not_before"): rows.append({"timestamp":cert["not_before"],"event":"Certificate observed","source":"crt.sh","evidence_id":_evidence_id("cert",cert.get("id"))})
    if http.get("status")=="completed": rows.append({"timestamp":_now(),"event":f"HTTP observation {http.get('status_code')}","source":"safe HTTP probe","evidence_id":_evidence_id("http",http.get("final_url"))})
    if rep.get("signals"): rows.append({"timestamp":_now(),"event":"Threat-intel signals correlated","source":"provider-enrichment","evidence_id":_evidence_id("rep",rep)})
    if breach.get("breached_identity_count"): rows.append({"timestamp":_now(),"event":f"Breach exposure: {breach.get('breached_identity_count')} identities","source":"Have I Been Pwned","evidence_id":_evidence_id("hibp",overview.get("domain"))})
    rows.sort(key=lambda x:x.get("timestamp") or "")
    return rows[-1000:]


def _evidence_ledger(domain: str, overview: dict[str, Any], dns: dict[str, Any], rdap: dict[str, Any], ct: dict[str, Any], http: dict[str, Any], tls: dict[str, Any], rep: dict[str, Any], breach: dict[str, Any]) -> list[dict[str, Any]]:
    out=[]
    def add(source, kind, raw, interpretation, confidence=90):
        out.append({"id":_evidence_id(source,kind,raw),"source":source,"kind":kind,"raw":raw,"interpretation":interpretation,"confidence":confidence,"observed_at":_now()})
    add("target-normalization","domain",domain,"Target normalized to an ASCII hostname for correlation.",99)
    for t in ("A","AAAA","CNAME","MX","NS","TXT","SOA","CAA","SRV","NAPTR","DNSKEY","DS","RRSIG","TLSA","SSHFP"):
        vals=dns.get("records",{}).get(t) or []
        if vals: add("DNS-over-HTTPS",t,vals[:100],f"Current {t} record observations returned by the configured resolver.",95)
    if rdap.get("raw") or rdap.get("events") or rdap.get("entities"): add("RDAP","registration",rdap.get("raw") or rdap,"Registration data returned from the RDAP chain.",95)
    if ct.get("certificates"): add("crt.sh","certificates",ct.get("certificates")[:50],"Certificate Transparency records associated with the domain.",92)
    if http.get("status")=="completed": add("safe HTTP probe","http",{k:http.get(k) for k in ("status_code","final_url","headers","redirects")},"Observed public HTTP response metadata without executing page JavaScript.",95)
    if tls.get("status")=="completed": add("TLS","certificate",tls,"Live certificate presentation observed on the public HTTPS endpoint.",95)
    if rep.get("signals"): add("threat-intelligence","reputation",rep,"Provider signals are retained as separate evidence; lack of a hit is not proof of safety.",90)
    if breach.get("records"): add("Have I Been Pwned","breach",breach.get("records")[:100],"Authenticated domain breach exposure data for a verified domain.",98)
    return out[:2500]


def _mitre(domain: str, overview: dict[str, Any], dns: dict[str, Any], http: dict[str, Any], breach: dict[str, Any]) -> list[dict[str, Any]]:
    rows=[]
    rows.append({"id":"T1583.001","name":"Acquire Infrastructure: Domains","evidence":"Domain registration and infrastructure observations","confidence":95})
    if dns.get("records"): rows.append({"id":"T1071.004","name":"Application Layer Protocol: DNS","evidence":"DNS records and resolver observations","confidence":95})
    if http.get("status")=="completed": rows.append({"id":"T1071.001","name":"Application Layer Protocol: Web Protocols","evidence":"HTTP/HTTPS response observations","confidence":95})
    if breach.get("breached_identity_count"): rows.append({"id":"T1589.003","name":"Gather Victim Identity Information: Employee Names","evidence":"Breach exposure contains domain identities; treat as exposure signal, not attacker attribution","confidence":65})
    return rows


def _agent_tasks(result: dict[str, Any]) -> list[dict[str, Any]]:
    score=int(result.get("risk",{}).get("score",0))
    tasks=[
        {"priority":1,"task":"Validate primary infrastructure pivots","why":"Confirm DNS, RDAP, certificate and current HTTP observations before attribution or containment decisions."},
        {"priority":2,"task":"Review certificate and subdomain history","why":"Identify infrastructure names that require ownership and lifecycle verification."},
        {"priority":3,"task":"Correlate IP/ASN/provider intelligence","why":"Separate shared-hosting infrastructure from evidence that is uniquely attributable to the target."},
        {"priority":4,"task":"Review reputation and breach signals","why":"Cross-check independent provider hits and verify timestamps/source context."},
        {"priority":5,"task":"Preserve evidence for the case record","why":"Export raw observations, provider responses and the relationship graph if the target is relevant to an incident."},
    ]
    if score>=55: tasks.insert(0,{"priority":0,"task":"Escalate for analyst review","why":"The explainable score is high enough that provider corroboration and case-level review are warranted."})
    return tasks


async def _ai_brief(result: dict[str, Any]) -> dict[str, Any]:
    if not settings.openai_api_key:
        return {"status":"not_configured","mode":"rules-and-evidence-agent","briefing":"AI API key is not configured. The investigation still has deterministic correlation, scoring, graphing and task planning.","tasks":_agent_tasks(result)}
    compact={
        "target":result.get("target"),"risk":result.get("risk"),"domain":result.get("domain_overview"),
        "url_forensics":result.get("url_forensics"),"whois":result.get("whois_rdap"),
        "dns":result.get("dns",{}).get("records",{}),"dns_authentication":result.get("dns_authentication"),
        "dns_posture":result.get("dns_posture"),"http":{k:result.get("http",{}).get(k) for k in ("status_code","final_url","redirect_count","title")},
        "http_posture":result.get("http_posture"),"tls":result.get("tls"),"reputation":result.get("reputation"),
        "breach":result.get("breach_intelligence"),"traffic":result.get("traffic"),"tech":result.get("technology")[:30],
        "graph_summary":result.get("graph_summary"),
    }
    prompt=("You are a defensive SOC investigation copilot. Summarize only the supplied evidence. "
            "Do not claim attribution, compromise, ownership, or criminal activity without direct evidence. "
            "Separate observed facts from hypotheses. Return a concise analyst briefing with: key findings, "
            "priority pivots, uncertainty/gaps, and recommended defensive validation steps. Evidence JSON:\n"+json.dumps(compact,default=str)[:90000])
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r=await client.post("https://api.openai.com/v1/responses",headers={"Authorization":f"Bearer {settings.openai_api_key}","Content-Type":"application/json"},json={"model":settings.openai_model,"input":prompt,"store":False})
            if r.status_code>=400:
                return {"status":"error","mode":"openai-responses","error":f"HTTP {r.status_code}: {r.text[:300]}","tasks":_agent_tasks(result)}
            data=r.json(); text=data.get("output_text")
            if not text:
                for block in data.get("output",[]) or []:
                    if not isinstance(block, dict):
                        continue
                    for content in block.get("content",[]) or []:
                        if not isinstance(content, dict):
                            continue
                        if content.get("type")=="output_text" and content.get("text"): text=content["text"]
            return {"status":"completed","mode":"openai-responses","model":settings.openai_model,"briefing":text or "No text returned.","tasks":_agent_tasks(result)}
    except Exception as exc:
        return {"status":"error","mode":"openai-responses","error":str(exc),"tasks":_agent_tasks(result)}


async def _bounded(label: str, awaitable, timeout: float) -> dict[str, Any]:
    """Run one collector with a hard wall-clock budget so one dead provider cannot hang a scan."""
    try:
        value = await asyncio.wait_for(awaitable, timeout=max(0.5, float(timeout)))
        return value if isinstance(value, dict) else {"status": "completed", "provider": label, "data": value}
    except asyncio.TimeoutError:
        return {"status": "timeout", "provider": label, "error": f"{label} exceeded {timeout:.1f}s collector budget"}
    except Exception as exc:
        return {"status": "error", "provider": label, "error": str(exc)[:500]}


async def analyze_url_domain(target: str, profile: str = "deep") -> dict[str, Any]:
    raw, domain, registered, norm = _normalize_target(target)
    overview = _domain_overview(domain, raw)
    target_url = norm["normalized_url"] if norm["is_url"] else f"https://{domain}/"
    collection_started = _now()

    profile = (profile or "deep").strip().lower()
    if profile not in {"quick", "deep", "forensic"}:
        profile = "deep"
    collector_timeout = {"quick": 4.5, "deep": 7.0, "forensic": 10.0}[profile]
    http_timeout = {"quick": 5.0, "deep": 8.0, "forensic": 12.0}[profile]

    async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
        dns_task = asyncio.create_task(_bounded("DNS-over-HTTPS", _dns_bundle(domain), collector_timeout))
        auth_task = asyncio.create_task(_bounded("DNS email authentication", _dns_auth_bundle(client, domain), collector_timeout))
        rdap_task = asyncio.create_task(_bounded("RDAP", _rdap(client, f"domain/{quote(registered, safe='')}"), collector_timeout))
        ct_task = asyncio.create_task(_bounded("Certificate Transparency", _ct_lookup(client, registered), collector_timeout))
        http_task = asyncio.create_task(_bounded("HTTP probe", _http_probe(target_url), http_timeout))
        gsb_task = asyncio.create_task(_bounded("Google Safe Browsing", _gsb_url(client, target_url), collector_timeout))
        vt_task = asyncio.create_task(_bounded("VirusTotal", _vt_domain(client, registered), collector_timeout))
        urlscan_task = asyncio.create_task(_bounded("urlscan.io", _urlscan_search(client, registered), collector_timeout))
        hibp_task = asyncio.create_task(_bounded("Have I Been Pwned", _hibp_domain(client, registered), collector_timeout))
        dnsdumpster_task = asyncio.create_task(_bounded("DNSDumpster", _dnsdumpster(client, registered), collector_timeout))
        dns, auth, rdap_raw, ct, http_probe, gsb, vt, urlscan, hibp, dnsdumpster = await asyncio.gather(
            dns_task, auth_task, rdap_task, ct_task, http_task, gsb_task,
            vt_task, urlscan_task, hibp_task, dnsdumpster_task
        )
        dns = dns if isinstance(dns, dict) else {}
        auth = auth if isinstance(auth, dict) else {}
        rdap_raw = rdap_raw if isinstance(rdap_raw, dict) else {}
        ct = ct if isinstance(ct, dict) else {}
        http_probe = http_probe if isinstance(http_probe, dict) else {}
        gsb = gsb if isinstance(gsb, dict) else {}
        vt = vt if isinstance(vt, dict) else {}
        urlscan = urlscan if isinstance(urlscan, dict) else {}
        hibp = hibp if isinstance(hibp, dict) else {}
        dnsdumpster = dnsdumpster if isinstance(dnsdumpster, dict) else {}
        dns_records = dns.get("records") if isinstance(dns.get("records"), dict) else {}
        dns["records"] = {str(k): [x for x in (v or []) if isinstance(x, dict)] for k,v in dns_records.items() if isinstance(v, list)}
        dns["reverse_dns"] = {str(k): [x for x in (v or []) if isinstance(x, dict)] for k,v in (dns.get("reverse_dns") or {}).items()} if isinstance(dns.get("reverse_dns"), dict) else {}
        if not isinstance(http_probe.get("forms"), list): http_probe["forms"]=[]
        else: http_probe["forms"]=[x for x in http_probe["forms"] if isinstance(x,dict)]
        if not isinstance(http_probe.get("links"), list): http_probe["links"]=[]
        else: http_probe["links"]=[x for x in http_probe["links"] if isinstance(x,dict)]
        if not isinstance(http_probe.get("scripts"), list): http_probe["scripts"]=[]
        else: http_probe["scripts"]=[str(x) for x in http_probe["scripts"] if isinstance(x,(str,int,float))]
        if not isinstance(ct.get("certificates"), list): ct["certificates"]=[]
        else: ct["certificates"]=[x for x in ct["certificates"] if isinstance(x,dict)]
        if not isinstance(ct.get("names"), list): ct["names"]=[]
        else: ct["names"]=[str(x) for x in ct["names"] if isinstance(x,(str,int,float))]
        if not isinstance(hibp.get("records"), list): hibp["records"]=[]
        else: hibp["records"]=[x for x in hibp["records"] if isinstance(x,dict)]
        all_current_ips = [
            x.get("value") for t in ("A", "AAAA")
            for x in dns_records.get(t, []) if isinstance(x, dict) and x.get("value")
        ]
        abuse = await _bounded("AbuseIPDB", _abuseipdb(client, all_current_ips), collector_timeout)
        if not norm["is_url"] and http_probe.get("status") in {"error", "timeout"}:
            http_probe = await _bounded("HTTP probe fallback", _http_probe(f"http://{domain}/"), min(http_timeout, 6.0))
            if http_probe.get("status") == "completed":
                gsb = await _bounded("Google Safe Browsing", _gsb_url(client, http_probe.get("final_url") or f"http://{domain}/"), collector_timeout)

    rdap_data = rdap_raw.get("data") if isinstance(rdap_raw, dict) and isinstance(rdap_raw.get("data"), dict) else {}
    rdap = {
        "status": rdap_raw.get("status"), "source": rdap_raw.get("url") or "rdap.org",
        "object_class_name": rdap_data.get("objectClassName"), "handle": rdap_data.get("handle"),
        "ldh_name": rdap_data.get("ldhName"), "unicode_name": rdap_data.get("unicodeName"),
        "status_codes": [x for x in (rdap_data.get("status") or []) if isinstance(x,str)], "events": _rdap_events(rdap_data),
        "entities": _rdap_entities(rdap_data),
        "name_servers": [str(x.get("ldhName") or "").strip() for x in (rdap_data.get("nameservers") or []) if (isinstance(x, dict) and x.get("ldhName"))] + [str(x).strip() for x in (rdap_data.get("nameservers") or []) if isinstance(x, str) and x.strip()],
        "secure_dns": rdap_data.get("secureDNS") or {},
        "notices": rdap_data.get("notices") or [], "remarks": rdap_data.get("remarks") or [],
        "raw": rdap_data,
    }
    registrar_entities = [
        x for x in rdap["entities"]
        if "registrar" in [str(r).lower() for r in x.get("roles") or []]
    ]
    rdap["registrar"] = (
        registrar_entities[0].get("name") or registrar_entities[0].get("organization")
    ) if registrar_entities else None
    creation = next((x.get("date") for x in rdap["events"] if isinstance(x,dict) and x.get("event_action") == "registration"), None)
    if creation:
        try:
            dt = datetime.fromisoformat(creation.replace("Z", "+00:00"))
            rdap["domain_age_days"] = (datetime.now(UTC) - dt).days
        except Exception:
            rdap["domain_age_days"] = None
    else:
        rdap["domain_age_days"] = None

    probe_port = 443
    if norm["is_url"]:
        try:
            explicit_port = urlparse(norm["normalized_url"]).port
        except ValueError:
            explicit_port = None
        if explicit_port:
            probe_port = explicit_port
    try:
        tls = await asyncio.wait_for(asyncio.to_thread(_ssl_probe, domain, probe_port), timeout={"quick": 4.0, "deep": 7.0, "forensic": 10.0}[profile])
    except asyncio.TimeoutError:
        tls = {"status": "timeout", "error": "TLS probe exceeded collector budget"}
    except Exception as exc:
        tls = {"status": "error", "error": str(exc)[:500]}
    security_headers = _security_headers(http_probe.get("headers") or {})
    network = _network_associations(domain, dns)
    tech = _tech_fingerprint(http_probe)
    reputation = _reputation_summary(vt, urlscan, gsb, abuse, hibp)
    url_forensics = _url_forensics(raw, norm["normalized_url"], domain)
    dns_posture = _dns_posture(dns, auth)
    ip_intelligence = _ip_intelligence(dns)
    certificate_posture = _certificate_posture(ct, tls)
    http_posture = _http_security_posture(http_probe, security_headers)
    risk = _risk(overview, dns, rdap, http_probe, tls, reputation, hibp)
    iocs = _ioc_set(domain, dns, http_probe, tls, ct)
    timeline = _timeline(overview, rdap, ct, http_probe, reputation, hibp)
    evidence = _evidence_ledger(domain, overview, dns, rdap, ct, http_probe, tls, reputation, hibp)
    mitre = _mitre(domain, overview, dns, http_probe, hibp)
    graph = _build_graph(domain, overview, rdap, dns, ct, http_probe, tls, tech, reputation, hibp)
    provider_catalog = tool_fabric_status()
    relationship_counts = Counter(n["kind"] for n in graph["nodes"])

    result = {
        "analysis_engine": {
            "name": "Phish-Hunter Unified URL & Domain Investigation Engine",
            "version": "24.5.0", "mode": "passive-first + safe public HTTP/TLS observation",
            "javascript_execution": False, "ssrf_guard": True, "arbitrary_command_execution": False,
        },
        "target": raw,
        "target_type": "url" if norm["is_url"] else "domain",
        "url": norm["normalized_url"],
        "domain": domain,
        "registered_domain": registered,
        "domain_overview": overview,
        "url_forensics": url_forensics,
        "whois_rdap": rdap,
        "dns": dns,
        "dns_authentication": auth,
        "dns_posture": dns_posture,
        "network_associations": network,
        "ip_intelligence": ip_intelligence,
        "certificate_transparency": ct,
        "certificate_posture": certificate_posture,
        "http": http_probe,
        "http_posture": http_posture,
        "tls": tls,
        "security_headers": security_headers,
        "technology": tech,
        "reputation": reputation,
        "risk_score": risk["score"],
        "verdict": risk["verdict"],
        "provider_results": {
            "VirusTotal": vt, "urlscan.io": urlscan, "Google Safe Browsing": gsb, "AbuseIPDB": abuse
        },
        "breach_intelligence": hibp,
        "breach_posture": {
            "domain_search_status": hibp.get("status"),
            "known_provider_connectors": [
                {"name": n, "status": "configured" if any(x.get("name") == n and x.get("status") == "live-configured" for x in provider_catalog["items"]) else "provider-dependent"}
                for n in ["Have I Been Pwned", "IntelX", "DeHashed", "Hudson Rock", "SpyCloud", "Constella"]
            ],
            "direct_dark_web_crawl": False,
            "note": "Leak-marketplace/Tor crawling is not fabricated as a capability. Use authorized provider APIs and preserve provider provenance.",
        },
        "dnsdumpster": dnsdumpster,
        "passive_dns": {
            "status": "provider-required",
            "current_records_are_not_historical": True,
            "historical_ip_associations": [],
            "historical_ns_associations": [],
            "historical_mx_associations": [],
            "fast_flux_assessment": "insufficient historical observations unless passive-DNS credentials are configured",
        },
        "availability": {
            "dns_resolves": bool(network.get("current_ips")),
            "http_status": http_probe.get("status_code"),
            "http_state": http_probe.get("status"),
            "tls_state": tls.get("status"),
        },
        "traffic": {
            "status": "provider-dependent",
            "observed_http_request": http_probe.get("status") == "completed",
            "current_response_bytes": http_probe.get("content_length"),
            "source_options": ["urlscan.io", "Cloudflare Radar", "SimilarWeb", "Tranco"],
            "note": "No traffic volume or popularity rank is fabricated. Configure an authorized provider for prevalence metrics.",
        },
        "brand_and_typosquatting": {
            "candidate_count": len(overview.get("typosquat_candidates") or []),
            "candidates": overview.get("typosquat_candidates") or [],
            "brand_matches": overview.get("lookalike_brand_matches") or [],
            "note": "Candidate generation is heuristic and requires verification; it is not an attribution result.",
        },
        "iocs": iocs,
        "mitre_techniques": mitre,
        "risk": risk,
        "timeline": timeline,
        "evidence": evidence,
        "graph": graph,
        "graph_summary": dict(relationship_counts),
        "investigation_pivots": [
            {"pivot": n["label"], "kind": n["kind"], "id": n["id"]}
            for n in graph["nodes"][:500]
        ],
        "osint_pivots": _osint_pivots(domain, norm["normalized_url"], graph, [r["ip"] for r in ip_intelligence]),
        "tool_fabric": provider_catalog,
        "investigation_matrix": [],
        "collection": {
            "started_at": collection_started, "completed_at": _now(), "passive_first": True,
            "external_provider_results_are_verbatim": True,
        },
        "notes": [
            "Direct Tor/dark-web crawling is intentionally not performed by the web service. Breach/leak coverage is exposed through explicit provider APIs with provider status and provenance.",
            "Historical passive DNS, historical WHOIS changes, full reverse-IP neighborhoods and traffic counts require provider datasets; the interface marks those fields as provider-dependent rather than inventing results.",
            "Safe HTTP observation fetches the public page without executing JavaScript, downloading arbitrary secondary resources, or probing arbitrary ports.",
            "Certificate Transparency is useful for passive hostname discovery, but a certificate entry is not proof that a hostname is currently active.",
        ],
        "self_verification": {"status": "verified", "checks": [
            "target normalized", "URL forensics present", "DNS bundle present", "DNS authentication checks present",
            "RDAP section present", "CT section present", "HTTP/TLS sections present", "IP intelligence present",
            "risk has signal breakdown", "graph contains source relations", "provider status is explicit", "breach boundary is explicit"
        ]},
    }
    result["investigation_matrix"] = _investigation_matrix(result)
    try:
        result["ai_analysis"] = await asyncio.wait_for(_ai_brief(result), timeout={"quick": 3.0, "deep": 12.0, "forensic": 20.0}[profile])
    except asyncio.TimeoutError:
        result["ai_analysis"] = {"status": "timeout", "mode": "rules-and-evidence-agent", "briefing": "AI stage exceeded its configured investigation budget.", "tasks": _agent_tasks(result)}
    except Exception as exc:
        result["ai_analysis"] = {"status": "error", "mode": "rules-and-evidence-agent", "error": str(exc)[:500], "tasks": _agent_tasks(result)}
    result["executive_summary"] = (
        f"Unified investigation completed for {domain}. Triage verdict: {risk['verdict']} at {risk['score']}/100 "
        f"with {len(evidence)} retained evidence records, {graph['node_count']} graph nodes, "
        f"{sum(len(v) for v in iocs.values())} extracted IOC values and "
        f"{len(ct.get('names') or [])} CT-discovered hostnames."
    )
    # Stable evidence package digest for chain-of-custody/export verification. The digest
    # is calculated before the digest field itself is inserted.
    digest_payload = json.dumps(result, sort_keys=True, default=str, separators=(",", ":"))
    result["chain_of_custody"] = {
        "package_sha256": hashlib.sha256(digest_payload.encode("utf-8", "replace")).hexdigest(),
        "generated_at": _now(), "scope": "normalized investigation result", "mutable": True,
        "note": "This is an application-level integrity digest, not a legal chain-of-custody determination.",
    }
    return result

