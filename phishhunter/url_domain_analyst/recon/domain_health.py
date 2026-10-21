from __future__ import annotations
from typing import Any


CHECK_MODULES={
 'DNS Records':'dns','DNS Health':'dns','IP & ISP':'attack-surface','Reverse DNS':'attack-surface','CDN Bypass':'hosting','MX Analysis':'dns','SPF Chain':'dns','Mail Security':'security','RDAP / WHOIS':'registration','BGP / ASN':'hosting','SSL / crt.sh':'certs','Reverse IP':'hosting','DNSSEC Chain':'dns','HTTP / HTTPS':'web','Web Policy':'web','TLS Posture':'certs','CAA':'dns','DMARC':'dns','DKIM':'security','Passive DNS':'dns-intel','Certificate Reuse':'certs','Technology Stack':'web','Corporate Branches':'workforce','GeoIP':'geo','Hosting / Cloud':'hosting','Services / Banners':'services','Threat Reputation':'breach','Breach Exposure':'breach',
}
CHECK_PIVOTS={
 'DNS Records':['open DNS full stack','inspect DNS lookup matrix','pivot discovered hosts'],
 'DNS Health':['compare authoritative/recursive answers','open DNS security posture'],
 'IP & ISP':['open attack surface','pivot ASN/network','locate public IPs on Global Live Map'],
 'Reverse DNS':['open attack surface','pivot PTR hostnames'],
 'CDN Bypass':['open hosting/network correlations','review origin-exposure evidence'],
 'MX Analysis':['open DNS full stack','pivot mail providers'],
 'SPF Chain':['inspect TXT chain','review mail security'],
 'Mail Security':['open Security Stack','review SPF/DKIM/DMARC'],
 'RDAP / WHOIS':['open registration intelligence','inspect registrar/entity history'],
 'BGP / ASN':['open hosting/networks','pivot prefixes/providers'],
 'SSL / crt.sh':['open Certificates/TLS','pivot CT SAN names'],
 'Reverse IP':['open hosting/networks','review reverse-IP evidence'],
 'DNSSEC Chain':['open DNS security posture','inspect DS/DNSKEY/RRSIG'],
 'HTTP / HTTPS':['open HTTP/Web Forensics','review redirect chain'],
 'Web Policy':['open HTTP/Web Forensics','inspect headers/cookies/CORS'],
 'TLS Posture':['open Certificates/TLS','inspect TLS posture'],
 'CAA':['open DNS full stack','review certificate issuance policy'],
 'DMARC':['open DNS full stack','review email security'],
 'DKIM':['open Security Stack','review candidate selectors'],
 'Passive DNS':['open DNS Lookup Matrix','review historical records'],
 'Certificate Reuse':['open Certificates/TLS','open Infrastructure Graph'],
 'Technology Stack':['open HTTP/Web Forensics','pivot technologies'],
 'Corporate Branches':['open Organization/Workforce','review provider-backed locations'],
 'GeoIP':['open Global Live Map','review provider coordinate evidence'],
 'Hosting / Cloud':['open Hosting/Networks','open Infrastructure Graph'],
 'Services / Banners':['open Services/Banners','pivot service products'],
 'Threat Reputation':['open Breach/Exposure','review threat feeds'],
 'Breach Exposure':['open Breach/Exposure','review authorized exposure providers'],
}

CHECKS = [
    ("DNS Records","📡","dns"),("DNS Health","🧭","dns_health"),("IP & ISP","🌐","ip"),("Reverse DNS","🔁","ptr"),
    ("CDN Bypass","🔓","cdn"),("MX Analysis","✉️","mx"),("SPF Chain","🔗","spf"),("Mail Security","📧","mail"),
    ("RDAP / WHOIS","📋","rdap"),("BGP / ASN","🗺️","asn"),("SSL / crt.sh","🔐","ct"),("Reverse IP","🔄","reverse_ip"),
    ("DNSSEC Chain","🛡️","dnssec"),("HTTP / HTTPS","🌍","http"),("Web Policy","📄","web_policy"),("TLS Posture","🔒","tls"),
    ("CAA","🧾","caa"),("DMARC","✉️","dmarc"),("DKIM","🔑","dkim"),("Passive DNS","🕰️","pdns"),
    ("Certificate Reuse","♻️","cert_reuse"),("Technology Stack","🧩","technology"),("Corporate Branches","🏢","branches"),("GeoIP","📍","geo"),
    ("Hosting / Cloud","☁️","hosting"),("Services / Banners","🛰️","services"),("Threat Reputation","🛡️","reputation"),("Breach Exposure","⚠️","breach"),
]


def _present(v: Any) -> bool:
    if v is None or v == "" or v == [] or v == {}: return False
    return True


def _records(dns: dict) -> dict:
    r=dns.get("records") if isinstance(dns,dict) else {}
    return r if isinstance(r,dict) else {}


def build(result: dict[str,Any], *, attack_surface=None, dns=None, whois=None, ct=None, http=None, tls=None,
          dnssec=None, mail=None, cdn=None, asn=None, registration=None, hosting=None, security_stack=None,
          pdns=None, branches=None, geo=None, cert_reuse=None, technology=None, breach=None, reputation=None) -> dict[str,Any]:
    surface=attack_surface or {}; dns=dns or {}; whois=whois or {}; ct=ct or {}; http=http or {}; tls=tls or {}
    dnssec=dnssec or {}; mail=mail or {}; cdn=cdn or {}; asn=asn or {}; registration=registration or {}
    hosting=hosting or {}; security_stack=security_stack or {}; pdns=pdns or {}; branches=branches or {}; geo=geo or {}
    cert_reuse=cert_reuse or {}; technology=technology or {}; breach=breach or {}; reputation=reputation or {}
    rec=_records(dns); txt=rec.get('TXT') or []; mx=rec.get('MX') or []
    ips=[]
    for r in surface.get('a_records') or []:
        if isinstance(r,dict) and r.get('ip'): ips.append(str(r['ip']))
    ips=sorted(set(ips))
    ptr=[r for r in surface.get('a_records') or [] if isinstance(r,dict) and r.get('ptr')]
    asn_rows=[r for r in surface.get('a_records') or [] if isinstance(r,dict) and r.get('asn')]
    spf=[r for r in txt if 'v=spf1' in str(r.get('value') or r.get('data') or '').lower()]
    dmarc=[r for r in txt if 'v=dmarc1' in str(r.get('value') or r.get('data') or '').lower()]
    caa=rec.get('CAA') or []
    checks=[]
    def add(name,icon,state,detail,needs,source,confidence=None,findings=None,recommendation=None,module=None,pivots=None):
        checks.append({'id':name.lower().replace(' ','_').replace('/','_'),'name':name,'icon':icon,'state':state,'detail':detail,
                       'needs':needs,'source':source,'confidence':confidence or ('observed' if state in ('HIT','OK','WARN') else 'not-observed'),
                       'findings':findings or [],'recommendation':recommendation or 'Review provider coverage and collect supporting evidence.',
                       'module':module or CHECK_MODULES.get(name,'overview'),'pivots':pivots or CHECK_PIVOTS.get(name,[])})
    n=sum(len(v or []) for v in rec.values())
    add('DNS Records','📡','HIT' if n else '—',f'{n} normalized records' if n else 'No DNS records observed','Domain','resolver/provider',findings=[f'{k}: {len(v or [])}' for k,v in rec.items() if v])
    add('DNS Health','🧭','OK' if n and not result.get('dns_error') else ('WARN' if result.get('dns_error') else '—'),
        'Delegation/record collection completed' if n and not result.get('dns_error') else ('Resolver/provider error recorded' if result.get('dns_error') else 'DNS health could not be evaluated'),
        'Domain','DNS engine',recommendation='Compare authoritative and recursive answers when resolver disagreement is observed.')
    add('IP & ISP','🌐','HIT' if ips else '—',f'{len(ips)} unique IP observations' if ips else 'No IP/ISP observation','Domain','attack surface / geolocation')
    add('Reverse DNS','🔁','HIT' if ptr else '—',f'{len(ptr)} PTR records found' if ptr else 'No PTR observation returned','Domain + resolved IP','attack surface')
    cdn_hit=bool(cdn.get('detected') or cdn.get('provider') or cdn.get('status') in ('detected','observed','hit'))
    add('CDN Bypass','🔓','HIT' if cdn_hit else '—',str(cdn.get('provider') or cdn.get('status') or 'No origin-bypass evidence returned'),'Domain + CDN/WAF provider','CDN/WAF analyzer',recommendation='Do not infer an origin IP from a CDN record alone; require provider-backed evidence.')
    add('MX Analysis','✉️','HIT' if mx else '—',f'{len(mx)} MX records' if mx else 'No MX records observed','Domain','DNS')
    add('SPF Chain','🔗','HIT' if spf else '—',f'SPF observed ({len(spf)} record(s))' if spf else 'No SPF TXT observation','Domain','DNS TXT')
    mail_hit=any(_present(v) and str(v).lower() not in {'unknown','not-observed','provider-dependent'} for v in mail.values())
    add('Mail Security','📧','HIT' if mail_hit else '—','Mail-authentication posture evaluated' if mail_hit else 'No mail-security observation','Domain','mail security analyzer')
    whois_hit=any(_present(v) for v in whois.values())
    add('RDAP / WHOIS','📋','HIT' if whois_hit else '—',f'{len(whois)} top-level fields returned' if whois_hit else 'RDAP/WHOIS unavailable','Domain','RDAP/WHOIS')
    asn_hit=bool(asn) or bool(asn_rows)
    asn_names=sorted({str(r.get('asn_name') or '') for r in asn_rows if r.get('asn_name')})
    add('BGP / ASN','🗺️','HIT' if asn_hit else '—',f'{len(asn_rows)} ASN-linked observations'+(f' · {", ".join(asn_names[:3])}' if asn_names else '') if asn_hit else 'No ASN observation','Domain/IP','ASN / attack surface')
    certs=ct.get('certificates') or []
    cert_count=ct.get('certificate_count') if ct.get('certificate_count') is not None else len(certs)
    add('SSL / crt.sh','🔐','HIT' if cert_count else '—',f'{cert_count} certificate observations' if cert_count else 'No CT/certificate observation','Domain','certificate transparency')
    revip=sum(int(r.get('reverse_ip_neighbor_count') or 0) for r in surface.get('a_records') or [] if isinstance(r,dict))
    add('Reverse IP','🔄','HIT' if revip else '—',f'{revip} returned relationship(s)' if revip else 'No reverse-IP relationship returned','IP + authorized dataset/API','reverse-IP provider')
    dnssec_state=str(dnssec.get('status') or '').lower()
    add('DNSSEC Chain','🛡️','HIT' if dnssec_state not in {'','unknown','not-observed','provider-dependent'} else '—',str(dnssec.get('status') or 'No DNSSEC observation'),'Domain','DNSSEC analyzer')
    http_code=http.get('status_code')
    add('HTTP / HTTPS','🌍','HIT' if http_code or http.get('headers') or http.get('url') else '—',f'{http_code}'+(f' · {http.get("response_time_ms")}ms' if http.get('response_time_ms') else '') if http_code else 'HTTP observation unavailable','Domain/URL','HTTP analyzer')
    headers=http.get('security_headers') or http.get('headers') or {}
    header_count=len(headers) if isinstance(headers,dict) else len(headers) if isinstance(headers,list) else 0
    add('Web Policy','📄','HIT' if header_count else '—',f'{header_count} security/header observations' if header_count else 'No web-policy observation','Domain/URL','HTTP/security stack')
    add('TLS Posture','🔒','HIT' if tls else '—',f'TLS posture analyzed'+(f' · {tls.get("grade")}' if tls.get('grade') else '') if tls else 'No TLS observation','Domain/URL','TLS analyzer')
    add('CAA','🧾','HIT' if caa else '—',f'{len(caa)} CAA records' if caa else 'No CAA record observed','Domain','DNS')
    add('DMARC','✉️','HIT' if dmarc else '—',f'Policy record observed ({len(dmarc)})' if dmarc else 'No DMARC TXT observation','Domain','DNS TXT')
    dkim=bool(mail.get('dkim_selectors') or mail.get('dkim'))
    add('DKIM','🔑','HIT' if dkim else '—','DKIM selector(s) observed' if dkim else 'No DKIM selector observation','Domain + selector candidates','mail security')
    pdns_hit=bool(pdns.get('history_events')) or (bool(pdns) and pdns.get('status') not in ('provider-required','provider-dependent',''))
    add('Passive DNS','🕰️','HIT' if pdns_hit else '—',f'{len(pdns.get("history_events") or [])} historical events' if pdns.get('history_events') else ('Provider-dependent' if not pdns_hit else 'Historical DNS evidence available'),'Domain + provider','passive DNS')
    reuse=cert_reuse.get('groups') or cert_reuse.get('reused') or cert_reuse
    add('Certificate Reuse','♻️','HIT' if reuse else '—','Certificate reuse relationships available' if reuse else 'No reuse observation','Domain + CT certificates','CT correlation')
    techs=technology if technology else result.get('technology') or result.get('wappalyzer') or []
    tech_count=len(techs) if isinstance(techs,(list,dict)) else 0
    add('Technology Stack','🧩','HIT' if tech_count else '—',f'{tech_count} technology observations' if tech_count else 'No technology observation','Domain/URL','HTTP/Wappalyzer')
    branch_rows=branches.get('locations') or []
    add('Corporate Branches','🏢','HIT' if branch_rows else '—',f'{len(branch_rows)} provider-backed locations' if branch_rows else 'No provider-backed branches','Domain + corporate provider','corporate/provider evidence')
    geo_points=geo.get('map_points') or []
    geo_countries=geo.get('countries') or []
    add('GeoIP','📍','HIT' if geo_points or geo_countries else '—',f'{len(geo_points)} exact/provider coordinates · {len(geo_countries)} country observations' if geo_points or geo_countries else 'No provider geolocation','IP + geolocation provider','geolocation provider')
    host_hit=bool(hosting or result.get('cloud_attribution'))
    add('Hosting / Cloud','☁️','HIT' if host_hit else '—','Hosting/cloud correlation available' if host_hit else 'No hosting correlation','Domain/IP','hosting/cloud')
    svc=surface.get('services') or result.get('services_banners') or []
    add('Services / Banners','🛰️','HIT' if svc else '—',f'{len(svc) if isinstance(svc,list) else 1} service/banner observations' if svc else 'No service observations','IP + authorized provider','service analyzer')
    rep_hit=bool(reputation or result.get('reputation_fusion') or result.get('reputation'))
    add('Threat Reputation','🛡️','HIT' if rep_hit else '—','Reputation signals available' if rep_hit else 'No reputation provider observation','Domain/IP + reputation providers','reputation')
    breach_rows=breach.get('records') or []
    add('Breach Exposure','⚠️','HIT' if breach_rows else '—',f'{len(breach_rows)} provider-confirmed exposure records' if breach_rows else 'Provider confirmation required','Authorized email/domain exposure provider','authorized exposure provider')
    hit=sum(x['state']=='HIT' for x in checks); ok=sum(x['state']=='OK' for x in checks); warn=sum(x['state']=='WARN' for x in checks); na=sum(x['state']=='—' for x in checks)
    return {'version':'DOMINUS-RECON-V29','target':result.get('domain') or result.get('target'),'checks':checks,
            'summary':{'total':len(checks),'hit':hit,'ok':ok,'warn':warn,'unavailable':na,'coverage_percent':round((hit+ok+warn)/len(checks)*100,1)},
            'policy':{'passive_first':True,'provider_truth_required':True,'no_fabricated_counts':True,'active_modules_require_explicit_scope':True},
            'next_actions':[x for c in checks for x in ([c['recommendation']] if c['state']=='—' else [])][:12]}
