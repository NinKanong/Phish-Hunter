from __future__ import annotations
from typing import Any
from .tool_catalog import TOOL_CATALOG, stats as tool_stats

MODULES=[
 {'id':'M1','name':'Passive OSINT Gathering','mode':'passive','goal':'Collect CT, passive DNS, public records, search, code-repository and threat-intel evidence without directly probing target infrastructure.','tools':['Amass','Subfinder','Assetfinder','Findomain','crt.sh','SecurityTrails','VirusTotal','DNSDumpster','SpiderFoot','theHarvester'],'outputs':['subdomains','certificates','historical_dns','public_mentions','repositories','relationships']},
 {'id':'M2','name':'Permutation & Family Engine','mode':'analysis/passive-first','goal':'Generate domain-family candidates from observed labels, brands and authorized wordlists; candidates remain hypotheses until resolved.','tools':['dnsgen','AlterX','Gotator','dnstwist','urlcrazy'],'outputs':['candidate_domains','typosquats','homoglyphs','dev/stage variants']},
 {'id':'M3','name':'Active DNS Enumeration','mode':'authorized-active','goal':'Resolve and validate candidates, test wildcard behavior and perform zone-transfer checks only inside an explicit allowlist.','tools':['MassDNS','PureDNS','ShuffleDNS','DNSx','DNSRecon','Fierce'],'outputs':['A','AAAA','CNAME','MX','NS','TXT','PTR','wildcard_state','axfr_state']},
 {'id':'M4','name':'Authorized Internal / AD Enumeration','mode':'authorized-internal','goal':'Map internal domains, LDAP objects, SPNs, DNS and trust relationships only with explicit credentials and scope.','tools':['BloodHound CE','SharpHound','ldapsearch','Impacket','NetExec','ADExplorer'],'outputs':['domains','users','groups','computers','spns','trusts','dns_zones']},
 {'id':'M5','name':'Resolution & Validation','mode':'authorized-active','goal':'Deduplicate and validate candidate domains, normalize DNS answers and suppress wildcard false positives.','tools':['PureDNS','MassDNS','DNSx','dnspython'],'outputs':['validated_hosts','resolver_agreement','wildcard_clusters','canonical_records']},
 {'id':'M6','name':'Service / Web Fingerprinting','mode':'authorized-active','goal':'Collect bounded HTTP/TLS/service metadata for explicitly authorized hosts; no exploitation or credential testing.','tools':['httpx','WhatWeb','Wappalyzer','Nmap','Naabu','ZGrab2','testssl.sh'],'outputs':['status','title','headers','tls','technologies','service_metadata']},
 {'id':'M7','name':'Graph / Correlation / Reporting','mode':'analysis','goal':'Build an evidence graph and produce analyst-ready JSON, CSV, timelines, pivots and risk explanations.','tools':['Neo4j','Cytoscape.js','D3.js','Cartography','OpenSearch','DuckDB','SQLite'],'outputs':['graph','relationships','timeline','risk','evidence_package']},
]


def build(target:str, *, profile='deep', explicit_scope=False, internal_scope=False) -> dict[str,Any]:
    modules=[]
    for m in MODULES:
        allowed = m['mode'] in {'passive','analysis','analysis/passive-first'} or (m['mode']=='authorized-active' and explicit_scope) or (m['mode']=='authorized-internal' and internal_scope)
        modules.append({**m,'status':'ready' if allowed else 'gated','execution_policy':'enabled' if allowed else 'requires explicit authorization/scope'})
    return {'version':'DOMINUS-RECON-ARCH-2','target':target,'profile':profile,'modules':modules,'tool_catalog':tool_stats(),
            'pipeline':['input normalization','M1 passive OSINT','M2 family generation','M3 authorized DNS (gated)','M4 authorized internal/AD (gated)','M5 validation','M6 bounded service metadata (gated)','M7 graph/correlation/reporting'],
            'aggregation':{'deduplicate':True,'canonicalize':True,'provenance_per_observation':True,'conflict_tracking':True},
            'active_scope':{'explicit_scope':explicit_scope,'internal_scope':internal_scope,'default':'disabled','note':'Active and internal collection are never implicitly executed from a public web scan.'},
            'output_contracts':['JSON','CSV','evidence ledger','graph','timeline','analyst pivots']}
