from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import re

BASE = Path(__file__).resolve().parents[2]
SPEC_PATH = BASE.parent / 'Pasted markdown(9).md'

SERVICE_KEYS = {
    'EMAIL ANALYST': 'email-analyst', 'URL ANALYST': 'url-analyst', 'URL & DOMAIN ANALYST': 'url-domain-analyst', 'FILE ANALYST': 'file-analyst',
    'DOMAIN ANALYST': 'domain-analyst', 'IP ANALYST': 'ip-analyst', 'PCAP ANALYST': 'pcap-analyst',
    'MALWARE ANALYST': 'malware-analyst', 'RANSOMWARE ANALYST': 'ransomware-analyst', 'IOC ANALYST': 'ioc-analyst',
    'PHISHING KIT ANALYST': 'phishing-kit-analyst', 'THREAT INTELLIGENCE': 'threat-intelligence', 'SANDBOX': 'sandbox',
    'REPORTS': 'reports', 'CASES': 'cases', 'CAMPAIGNS': 'campaigns', 'ACTORS': 'actors',
    'IOC GRAPH': 'graph', 'FEEDS': 'feeds',
}

DEFAULT_CAPABILITIES = {
    'Evidence': ['raw evidence', 'interpretation', 'source reference', 'first seen / last seen'],
    'Confidence': ['0-100 calibrated confidence', 'confidence rationale'],
    'Threat Intelligence': ['configured-provider lookups', 'lookup timestamps', 'provider status'],
    'Timeline': ['event timestamp', 'observation timestamp', 'first/last seen'],
    'Correlation': ['related findings', 'related IOCs', 'graph pivot identifiers'],
    'MITRE ATT&CK': ['technique ID', 'technique name', 'evidence reference', 'confidence'],
    'Reporting': ['raw evidence appendix', 'machine-readable result', 'analyst report', 'self-verification'],
}


def _parse_spec() -> dict[str, list[dict]]:
    result = {key: [] for key in SERVICE_KEYS.values()}
    if not SPEC_PATH.exists():
        return {key: [{'name': name, 'items': items.copy()} for name, items in DEFAULT_CAPABILITIES.items()] for key in SERVICE_KEYS.values()}
    lines = SPEC_PATH.read_text(encoding='utf-8', errors='replace').splitlines()
    current = None
    section = None
    for line in lines:
        m = re.match(r'^## 2\.\d+\s+—\s+(.+?)\s*\(Deep\)', line.strip())
        if m:
            title = m.group(1).strip().upper()
            current = SERVICE_KEYS.get(title)
            section = None
            continue
        if not current:
            continue
        raw = line.strip()
        if not raw or raw.startswith(('```', 'svgsvg', 'text')):
            continue
        if raw.endswith('(deep)') or (raw and not raw.startswith(('├', '└', '│')) and raw.isupper() and len(raw) < 100):
            section = raw.replace('(deep)', '').strip()
            if section and section not in {x['name'] for x in result[current]}:
                result[current].append({'name': section, 'items': []})
            continue
        item = re.sub(r'^[│\s]*(?:├─|└─|─)\s*', '', raw).strip()
        if item and section and item not in {'For EVERY header:', 'For EVERY hop:', 'For EVERY attachment:', 'For EVERY URL:', 'For EVERY IOC:'}:
            for block in result[current]:
                if block['name'] == section:
                    if len(block['items']) < 80:
                        block['items'].append(item)
                    break
    for key in result:
        if not result[key]:
            result[key] = [{'name': name, 'items': items.copy()} for name, items in DEFAULT_CAPABILITIES.items()]
    return result

CAPABILITIES = _parse_spec()

UNIFIED_URL_DOMAIN_SECTIONS = [
    {'name':'Target normalization','items':['raw URL or domain','normalized URL','ASCII/IDNA hostname','registered domain','FQDN','URL vs domain classification','hostname length','entropy','subdomain depth','script profile','mixed-script detection','IDN homoglyph indicators']},
    {'name':'WHOIS / RDAP','items':['registrar','registration handle','creation / update / expiration events','status codes','public entity roles','public organization / email / phone / address','nameservers','secure DNS flags','notices and remarks','domain age']},
    {'name':'DNS and DNS security','items':['A','AAAA','CNAME','MX','NS','TXT','SOA','CAA','SRV','NAPTR','DNSKEY','DS','RRSIG','TLSA','SSHFP','per-record TTL','resolver/source','PTR','SPF','DMARC','DKIM selector boundary','DNSSEC evidence']},
    {'name':'Certificate transparency','items':['certificate count','certificate IDs','issuers','common names','SAN names','validity windows','serials','current passive host discovery']},
    {'name':'Web and URL intelligence','items':['HTTP status','headers','redirect chain','final URL','title','forms','password inputs','cross-origin form actions','external links','security headers','technology fingerprints','TLS version','TLS cipher','certificate fingerprint','availability']},
    {'name':'Passive infrastructure','items':['current IP associations','reverse DNS','ASN provider boundary','geolocation provider boundary','historical passive DNS provider boundary','historical WHOIS provider boundary','reverse-IP provider boundary','traffic provider boundary']},
    {'name':'Reputation and breach intelligence','items':['VirusTotal','urlscan.io','Google Safe Browsing','AbuseIPDB','Have I Been Pwned verified-domain search','provider timestamps','provider status','aggregate verdict','dark-web/leak connector boundary']},
    {'name':'Brand and typosquatting','items':['edit distance','deletion/insertion/substitution','transposition','hyphen variants','secure/login variants','homoglyphs','brand candidate boundary']},
    {'name':'Investigation graph','items':['domain','registered domain','URL','IP','reverse DNS','NS','MX','certificate','subdomain','technology','provider signal','breach identity','source-backed edge','relationship confidence']},
    {'name':'Risk and analyst workflow','items':['0-100 score','signal weights','contributions','confidence','observed vs inferred','priority pivots','defensive validation actions','timeline','machine-readable result','self-verification']},
    {'name':'Tool fabric','items':['200+ named integrations','live configured adapters','local CLI availability','catalog-only sources','fixed connector boundary','no arbitrary command execution','no arbitrary Tor crawling']},
]
CAPABILITIES.setdefault('url-domain-analyst', UNIFIED_URL_DOMAIN_SECTIONS)


def capability_manifest(service_key: str) -> dict:
    blocks = CAPABILITIES.get(service_key) or []
    return {
        'service': service_key,
        'depth_contract': 'K4-UNIVERSAL-DEPTH-1',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'universal_requirements': DEFAULT_CAPABILITIES,
        'deep_sections': blocks,
        'section_count': len(blocks),
        'capability_count': sum(len(x.get('items', [])) for x in blocks),
        'source_spec': 'Pasted markdown(9).md',
    }


def write_manifest(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({k: capability_manifest(k) for k in CAPABILITIES}, indent=2), encoding='utf-8')
