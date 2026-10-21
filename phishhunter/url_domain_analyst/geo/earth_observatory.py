from __future__ import annotations
from collections import OrderedDict
from typing import Any


def _has_records(records: Any, *types: str) -> bool:
    if not isinstance(records, dict):
        return False
    for t in types:
        if records.get(t):
            return True
    return False


def _status(observed: bool, *, healthy: bool | None = None, configured: bool = True) -> str:
    if not configured:
        return "—"
    if not observed:
        return "—"
    if healthy is False:
        return "WARN"
    return "OK" if healthy is not None else "HIT"


def _ip_rows(surface: dict, ip_geo: list[dict]) -> list[dict]:
    rows=[]
    for r in surface.get("a_records") or []:
        if isinstance(r, dict) and r.get("ip"):
            rows.append({
                "type":"ip", "ip":str(r.get("ip")), "host":r.get("host"),
                "asn":r.get("asn"), "asn_name":r.get("asn_name"),
                "country":r.get("country"), "country_code":r.get("country_code"),
                "ptr":r.get("ptr"), "source":r.get("source"),
            })
    for r in ip_geo or []:
        if isinstance(r, dict) and r.get("ip"):
            rows.append({
                "type":"ip", "ip":str(r.get("ip")), "host":None,
                "asn":r.get("asn") or r.get("as"), "asn_name":r.get("organization") or r.get("org"),
                "country":r.get("country") or r.get("country_name"), "country_code":r.get("country_code") or r.get("country"),
                "city":r.get("city"), "region":r.get("region"), "lat":r.get("lat"), "lon":r.get("lon"),
                "source":r.get("source") or "IP geolocation provider",
            })
    out=[]; seen=set()
    for r in rows:
        key=(r.get("ip"),r.get("source"),r.get("city"),r.get("lat"),r.get("lon"))
        if key in seen: continue
        seen.add(key); out.append(r)
    return out[:500]


def build(result: dict[str, Any], geo: dict[str, Any] | None, branches: dict[str, Any] | None,
          attack_surface: dict[str, Any] | None, dns: dict[str, Any] | None,
          whois: dict[str, Any] | None, ct: dict[str, Any] | None,
          http: dict[str, Any] | None, tls: dict[str, Any] | None,
          dnssec: dict[str, Any] | None, mail: dict[str, Any] | None,
          cdn: dict[str, Any] | None, asn: dict[str, Any] | None,
          registration: dict[str, Any] | None, hosting: dict[str, Any] | None,
          security_stack: dict[str, Any] | None, pdns: dict[str, Any] | None,
          company: dict[str, Any] | None = None) -> dict[str, Any]:
    surface=attack_surface or {}
    dns=dns or {}; records=dns.get("records") if isinstance(dns.get("records"),dict) else {}
    geo=geo or {}; branches=branches or {}; whois=whois or {}; ct=ct or {}; http=http or {}; tls=tls or {}
    dnssec=dnssec or {}; mail=mail or {}; cdn=cdn or {}; asn=asn or {}; registration=registration or {}
    hosting=hosting or {}; security_stack=security_stack or {}; pdns=pdns or {}
    ip_geo=result.get("ip_geolocation") if isinstance(result.get("ip_geolocation"),list) else []
    ips=_ip_rows(surface, ip_geo)

    checks=[]
    def add(name, icon, state, detail, source=None, action=None):
        checks.append({"name":name,"icon":icon,"state":state,"detail":detail,"source":source or "engine","action":action or "Open evidence"})

    add("DNS Records","📡",_status(bool(records)),f"{sum(len(v or []) for v in records.values())} normalized records" if records else "No DNS records observed","resolver / provider")
    add("DNS Health","🧭",_status(bool(records), healthy=(bool(records) and not result.get("dns_error"))),"Delegation and record collection completed" if records else "Resolver/provider observation unavailable","DNS engine")
    add("IP & ISP","🌐",_status(bool(ips) or bool(surface.get("a_records"))),f"{len({r.get('ip') for r in ips if r.get('ip')})} unique IP observations" if ips else "No IP/ISP observation","attack surface / geolocation")
    ptr=any(r.get("ptr") for r in surface.get("a_records") or [])
    add("Reverse DNS","🔁",_status(ptr),"PTR observed for at least one address" if ptr else "No PTR observation returned","attack surface")
    cdn_hit=bool(cdn.get("detected") or cdn.get("provider") or cdn.get("status") in ("detected","observed","hit"))
    add("CDN Bypass","🔓",_status(cdn_hit),str(cdn.get("provider") or cdn.get("status") or "No CDN/WAF bypass evidence"),"CDN/WAF analyzer")
    mx=records.get("MX") or []
    add("MX Analysis","✉️",_status(bool(mx)),f"{len(mx)} MX records" if mx else "No MX records observed","DNS records")
    spf=any("v=spf1" in str(r.get("value") or r.get("data") or "").lower() for r in records.get("TXT",[]) or [])
    add("SPF Chain","🔗",_status(spf),"SPF TXT record observed" if spf else "No SPF TXT observation","DNS TXT")
    mail_hit=bool(mail and any(v not in (None,"","unknown","not-observed") for v in mail.values()))
    add("Mail Security","📧",_status(mail_hit),"Mail-authentication posture evaluated" if mail_hit else "No mail-security observation","mail security analyzer")
    whois_hit=bool(whois) and any(v not in (None,"",[],{}) for v in whois.values())
    add("RDAP / WHOIS","📋",_status(whois_hit),"Registration evidence returned" if whois_hit else "RDAP/WHOIS unavailable","RDAP/WHOIS")
    asn_hit=bool(asn) or any(r.get("asn") for r in surface.get("a_records") or [])
    add("BGP / ASN","🗺️",_status(asn_hit),"ASN/network ownership observed" if asn_hit else "No ASN observation","ASN / attack surface")
    cert_hit=bool(ct.get("certificate_count") or ct.get("certificates") or result.get("certificate_posture"))
    add("SSL / crt.sh","🔐",_status(cert_hit),f"{ct.get('certificate_count',0)} certificate observations" if cert_hit else "No CT/certificate observation","certificate transparency")
    revip=any(int(r.get("reverse_ip_neighbor_count") or 0)>0 for r in surface.get("a_records") or [])
    add("Reverse IP","🔄",_status(revip),"Returned dataset contains reverse-IP relationships" if revip else "No reverse-IP relationship returned","attack surface")
    dnssec_hit=bool(dnssec) and str(dnssec.get("status") or "").lower() not in ("","unknown","not-observed","provider-dependent")
    add("DNSSEC Chain","🛡️",_status(dnssec_hit),str(dnssec.get("status") or "No DNSSEC observation"),"DNSSEC analyzer")
    http_hit=bool(http.get("status_code") or http.get("headers") or http.get("url") or result.get("availability",{}).get("http_state"))
    add("HTTP / HTTPS","🌍",_status(http_hit),f"HTTP status {http.get('status_code')}" if http.get("status_code") else "HTTP observation unavailable","HTTP analyzer")
    policy_hit=bool(http.get("headers") or http.get("security_headers") or security_stack.get("observations"))
    add("Web Policy","📄",_status(policy_hit),"Headers/policy evidence available" if policy_hit else "No web-policy observation","HTTP/security stack")
    add("TLS Posture","🔒",_status(bool(tls)),"TLS posture analyzed" if tls else "No TLS observation","TLS analyzer")
    add("CAA","🧾",_status(bool(records.get("CAA"))),f"{len(records.get('CAA') or [])} CAA records" if records.get("CAA") else "No CAA record observed","DNS")
    dmarc=any(str(r.get("value") or "").lower().startswith("v=dmarc1") for r in records.get("TXT",[]) or [])
    add("DMARC","✉️",_status(dmarc),"DMARC policy observed" if dmarc else "No DMARC TXT observation","DNS TXT")
    dkim=bool(mail.get("dkim_selectors") or mail.get("dkim"))
    add("DKIM","🔑",_status(dkim),"DKIM selectors observed" if dkim else "No DKIM selector observation","mail security")
    add("Passive DNS","🕰️",_status(bool(pdns) and pdns.get("status") not in ("provider-required","provider-dependent","")),"Historical DNS evidence available" if pdns.get("history_events") else "Provider-dependent","passive DNS")
    add("Certificate Reuse","♻️",_status(bool(result.get("certificate_reuse"))),"Certificate reuse analysis available" if result.get("certificate_reuse") else "No reuse observation","CT correlation")
    add("Technology Stack","🧩",_status(bool(result.get("technology") or result.get("wappalyzer"))),"Technology fingerprint observations available" if (result.get("technology") or result.get("wappalyzer")) else "No technology observation","HTTP / Wappalyzer")
    add("Corporate Branches","🏢",_status(bool(branches.get("locations"))),f"{branches.get('count',0)} provider-backed locations" if branches.get("locations") else "No provider-backed branches","corporate/provider evidence")
    add("GeoIP","📍",_status(bool(geo.get("map_points") or geo.get("countries"))),f"{len(geo.get('map_points') or [])} exact coordinates / {len(geo.get('countries') or [])} country observations" if (geo.get("map_points") or geo.get("countries")) else "No provider geolocation","geolocation provider")
    add("Hosting / Cloud","☁️",_status(bool(hosting or result.get("cloud_attribution"))),"Hosting/cloud correlation available" if hosting or result.get("cloud_attribution") else "No hosting correlation","hosting / cloud")
    add("Services / Banners","🛰️",_status(bool(surface.get("services") or result.get("services_banners"))),"Observed service/banner inventory available" if (surface.get("services") or result.get("services_banners")) else "No service observations","service analyzer")
    add("Threat Reputation","🛡️",_status(bool(result.get("reputation") or result.get("reputation_fusion"))),"Reputation signals available" if result.get("reputation") or result.get("reputation_fusion") else "No reputation provider observation","reputation")
    add("Breach Exposure","⚠️",_status(bool(result.get("breach_intelligence",{}).get("records") or result.get("breach_exposure",{}).get("records"))),"Authorized breach-provider evidence returned" if result.get("breach_intelligence",{}).get("records") else "Provider confirmation required","authorized exposure provider")

    # Build map entities. Country anchors are visualization anchors; exact points remain provider coordinates.
    entities=[]
    for r in ips:
        if r.get("lat") is not None and r.get("lon") is not None:
            entities.append({**r,"id":f"ip:{r.get('ip')}:{r.get('lat')}:{r.get('lon')}","precision":"provider-coordinate","layer":"network"})
    for r in geo.get("map_points") or []:
        if isinstance(r,dict) and r.get("lat") is not None and r.get("lon") is not None:
            entities.append({**r,"id":f"geo:{r.get('ip') or r.get('city') or len(entities)}:{r.get('lat')}:{r.get('lon')}","layer":"network","precision":"provider-coordinate"})
    for r in branches.get("locations") or []:
        if isinstance(r,dict) and r.get("lat") is not None and r.get("lon") is not None:
            entities.append({**r,"id":f"branch:{r.get('name') or r.get('city') or len(entities)}:{r.get('lat')}:{r.get('lon')}","layer":"company","precision":"corporate-provider"})
    # Keep country layers separately so the UI can click an observed country without implying an exact IP location.
    country_layers=geo.get("country_layers") or []
    signals=[]
    for i,e in enumerate(entities[:500]):
        signals.append({"id":e.get("id"),"kind":e.get("layer"),"label":e.get("city") or e.get("name") or e.get("ip") or "Observed location","severity":"info","source":e.get("source"),"lat":e.get("lat"),"lon":e.get("lon")})
    return {
        "version":"DOMINUS-EARTH-1",
        "target":result.get("domain") or result.get("target"),
        "status":"live-evidence-ready",
        "checks":checks,
        "check_summary":{
            "total":len(checks),
            "ok":sum(1 for x in checks if x["state"]=="OK"),
            "hit":sum(1 for x in checks if x["state"]=="HIT"),
            "warn":sum(1 for x in checks if x["state"]=="WARN"),
            "unavailable":sum(1 for x in checks if x["state"]=="—"),
        },
        "layers":[
            {"id":"target","label":"Target domain","enabled":True,"count":1},
            {"id":"network","label":"IP / network","enabled":True,"count":len(entities)},
            {"id":"countries","label":"Observed countries","enabled":True,"count":len(country_layers)},
            {"id":"company","label":"Company / branches","enabled":True,"count":len(branches.get("locations") or [])},
            {"id":"dns","label":"DNS relationships","enabled":True,"count":sum(len(v or []) for v in records.values())},
            {"id":"cert","label":"Certificate names","enabled":True,"count":len(ct.get("discovered_names") or [])},
            {"id":"asn","label":"ASN / hosting","enabled":True,"count":len([r for r in surface.get("a_records") or [] if r.get("asn")])},
        ],
        "entities":entities[:500],
        "country_layers":country_layers[:250],
        "signals":signals,
        "company":company or {},
        "controls":["layers","search","focus-target","fit-world","rotate","zoom","timeline","isolate","fullscreen","reset"],
        "evidence_policy":"Exact coordinates require provider evidence. Country centroids are visualization anchors only. Corporate branches require corporate/provider evidence. No employee home locations are inferred or plotted.",
    }
