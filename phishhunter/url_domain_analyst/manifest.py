from __future__ import annotations
TOOL_KEY='url-domain-analyst'
VERSION='29.0.0'
DISPLAY_NAME='URL & Domain Analyst'
MISSION='Deep URL + domain investigation: structure, identity, DNS, CT, infrastructure, web/TLS posture, threat intelligence, graph correlation, evidence and AI-assisted analyst planning.'
LAYERS={
1:'collection engine',2:'URL structure',3:'domain registry',4:'DNS intelligence',5:'certificate and security',6:'protocol analysis',
7:'content and visual',8:'behavioral and temporal',9:'correlation and knowledge graph',10:'AI reasoning',11:'delivery and workflow',12:'investigation experience'}
CAPABILITIES=['200+ URL decomposition contract','120+ domain decomposition contract','60+ DNS record contract','9 DNS resolution modes','WHOIS/RDAP lifecycle','certificate transparency','passive DNS provider boundary','subdomain enumeration','SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT','DNSSEC and CAA','IP/ASN/hosting/CDN/WAF correlation','HTTP/headers/cookies/forms/redirects','TLS posture','technology fingerprinting','homograph/IDN/typosquat/DGA heuristics','subdomain takeover candidates','reputation fusion','breach provider boundary','typed relationship graph','10-dimensional risk scoring','chain-of-custody evidence','watchlists and monitoring','AI evidence-grounded task planning','system location intelligence with provider-backed world map','hosting/network aggregation','service/banner normalization','advanced URL similarity','advanced typosquat generation','15-category Advanced OSINT','545-field OSINT evidence explorer','360-source/adapter catalog','real-world orthographic evidence globe with live earthquake/aircraft feeds','DNS temporal analysis','certificate reuse analysis','ASN/cloud attribution','deep OSINT pivot generation','provider exposure matrix','risk calibration and uncertainty','27-stage deep investigation plan','JSON/Markdown/HTML/CSV/STIX/XLSX/DOCX/PPTX/PDF report center']
SAFETY_BOUNDARY='Passive-first, evidence-backed analysis. No fabricated provider results, no arbitrary command execution from the web path, no dynamic detonation, and no direct dark-web crawler.'

def manifest()->dict:
    return {'key':TOOL_KEY,'version':VERSION,'title':DISPLAY_NAME,'mission':MISSION,'layers':LAYERS,'capabilities':CAPABILITIES,'safety_boundary':SAFETY_BOUNDARY}
