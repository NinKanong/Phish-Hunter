from __future__ import annotations
from . import __name__ as _pkg
from ..url.anatomy import analyze as analyze_url
from ..domain.anatomy import analyze as analyze_domain
from ..dns.analysis import analyze as analyze_dns
from ..rdap.analysis import lifecycle as analyze_rdap
from ..ct.analysis import analyze as analyze_ct
from ..infrastructure.associations import analyze as analyze_infra
from ..http.analysis import analyze as analyze_http
from ..tls.analysis import analyze as analyze_tls
from ..security.detections import typosquat_candidates, homograph_assessment, dga_score, dns_tunnel_score, takeover_candidates
from ..reputation.fusion import normalize as fuse_reputation
from ..breach.exposure import analyze as analyze_breach
from ..graph.builder import build as build_graph
from ..scoring.ten_dimensions import score as score_risk
from ..evidence.ledger import build as build_ledger
from ..pivots.suggestions import suggest
from ..ai.agent import task_plan
from ..monitoring.watch import manifest as monitoring_manifest
from ..geo.location_intel import build as build_geo
from ..services.banners import build as build_banners
from ..attack_surface import build as build_attack_surface
from ..url.similarity import similarity
from ..domain.typosquat import candidates as advanced_typosquats
from ..dns.temporal import summarize as summarize_dns_history
from ..certificates.reuse import analyze as analyze_cert_reuse
from ..infrastructure.asn import analyze as analyze_asn
from ..infrastructure.cloud import detect as detect_cloud
from ..osint.pivots import build as build_osint_pivots
from ..intelligence.exposure_matrix import build as build_exposure_matrix
from ..ai.deep_reasoning import build as build_deep_reasoning
from ..scoring.calibration import calibrate
from ..graph.layouts import contract as graph_layout_contract
from ..evidence.chain import summarize as summarize_chain
from ..monitoring.watch_engine import plan as watch_plan
from ..utils.types import as_dict
from ..connectors.providers.wappalyzer import lookup as wappalyzer_lookup
from ..connectors.providers.linkedin import organization_lookup as linkedin_org_lookup
from ..workforce.intelligence import build as build_workforce
from ..technology.third_party import build as build_third_party
from ..technology.security_stack import build as build_security_stack_observables
from ..infrastructure.cdn_waf import detect as detect_cdn_waf
from ..infrastructure.hosting_intel import summarize as summarize_hosting, infer_from_names
from ..domain.registration_intel import lifecycle as registration_lifecycle
from ..domain.domain_information import build as build_domain_information
from ..domain.contact_normalizer import normalize_entity
from ..dns.dns_lookup_matrix import build as build_dns_lookup_matrix
from ..geo.branch_locations import build as build_branch_locations
from ..geo.live_map_contract import build as build_live_map_contract
from ..geo.earth_observatory import build as build_earth_observatory
from ..connectors.providers.domaintools import investigate as domaintools_investigate, profile as domaintools_profile, whois as domaintools_whois, web_links as domaintools_web_links
from ..dns.mail_security import analyze as analyze_mail_security
from ..security.fast_flux import assess as assess_fast_flux
from ..security.typo_families import families as typo_families
from ..osint.company_profile import build as build_company_profile
from ..osint.search_plan import build as build_search_plan
from ..osint.breach_matrix import build as build_breach_matrix
from ..connectors.providers.ipinfo import lookup as ipinfo_lookup
from ..connectors.providers.securitytrails import domain as securitytrails_domain_lookup
from ..detection.dga import score as dga_detector
from ..detection.dns_tunneling import score as dns_tunnel_detector
from ..detection.c2_infrastructure import analyze as analyze_c2
from ..detection.infrastructure_cluster import build as build_infrastructure_cluster
from ..intelligence.analyst_matrix import build as build_analyst_matrix
from ..geo.world_index import layers as world_layers
from ..connectors.providers.public_geo import lookup_many as public_geo_lookup
from ..deep_intelligence.field_inventory import build as build_field_inventory
from ..deep_intelligence.domain_field_matrix import build as build_domain_field_matrix
from ..deep_intelligence.country_matrix import build as build_country_matrix
from ..deep_intelligence.service_matrix import build as build_service_matrix
from ..deep_intelligence.hosting_matrix import build as build_hosting_matrix
from ..deep_intelligence.osint_matrix import build as build_osint_matrix
from ..deep_intelligence.case_summary import build as build_case_summary
from ..advanced_osint import build_advanced_osint
from .stage_registry import plan as stage_plan
from .collection_plan import build as build_collection_plan
from ..services.service_catalog import normalize as normalize_service
from ..recon.domain_health import build as build_domain_health_recon
from ..recon.registrant_intelligence import build as build_registrant_intelligence
from ..recon.investigation_plan import build as build_recon_investigation_plan
from ..recon.tool_catalog import TOOL_CATALOG
from phishhunter.config import settings


async def augment(result: dict, target: str, progress_cb=None) -> dict:
    """Run the deep URL/domain pipeline without allowing one malformed provider payload to abort the case."""
    result = result if isinstance(result, dict) else {}
    result.setdefault("provider_results", {})
    result.setdefault("dns", {"records": {}, "reverse_dns": {}})
    result.setdefault("http", {})
    result.setdefault("tls", {})
    result.setdefault("certificate_transparency", {})
    result.setdefault("reputation", {"signals": [], "provider_states": {}})
    result.setdefault("breach_intelligence", {"records": [], "status": "provider-dependent"})
    errors=[]

    _progress_index = {"n": 0}
    _progress_total = 44
    def _emit(label, state, detail=None):
        if not progress_cb:
            return
        _progress_index["n"] += 1
        pct = min(98, 10 + int((_progress_index["n"] / _progress_total) * 88))
        try:
            progress_cb({"stage": label, "state": state, "percent": pct, "detail": detail or ""})
        except Exception:
            pass

    def safe_sync(label, fn, *args):
        _emit(label, "started")
        try:
            value=fn(*args)
            out = value if isinstance(value, dict) else {"status":"invalid_result","stage":label,"value":str(value)[:500]}
            _emit(label, "completed", str(out.get("status") or "observed")[:120])
            return out
        except Exception as exc:
            errors.append({"stage":label,"error":str(exc)[:500],"recoverable":True})
            _emit(label, "degraded", str(exc)[:180])
            return {"status":"error","stage":label,"error":str(exc)[:500]}

    url_info=safe_sync('url_anatomy', analyze_url, target, result.get('url'))
    domain_info=safe_sync('domain_anatomy', analyze_domain, result.get('domain') or domain_info_from_result(result))
    dns_info=safe_sync('dns_analysis', analyze_dns, result.get('dns'))
    rdap_info=safe_sync('rdap', analyze_rdap, result.get('whois_rdap'))
    ct_info=safe_sync('certificate_transparency', analyze_ct, result.get('certificate_transparency'), result.get('domain') or '')
    http_info=safe_sync('http_analysis', analyze_http, result.get('http'))
    tls_info=safe_sync('tls_analysis', analyze_tls, result.get('tls'), result.get('certificate_transparency'))
    infra_info=safe_sync('infrastructure', analyze_infra, result.get('ip_intelligence'), result.get('http'), result.get('dns'))
    rep_info=safe_sync('reputation', fuse_reputation, result.get('provider_results'))
    breach_info=safe_sync('breach', analyze_breach, result.get('breach_intelligence'))

    domain=result.get('domain') or domain_info.get('domain') or domain_info_from_result(result)
    brands=[]
    try: typo=typosquat_candidates(domain,brands)
    except Exception as exc: typo=[]; errors.append({'stage':'typosquatting','error':str(exc)[:500],'recoverable':True})
    labels=(domain_info.get('subdomain_labels') or [])+[domain_info.get('sld') or '']
    dga=[]
    for x in labels:
        if not x: continue
        try: dga.append({'label':x,**dga_score(x)})
        except Exception as exc: errors.append({'stage':'dga','error':str(exc)[:500],'recoverable':True})
    txt=[str(x.get('value') or '') for x in (as_dict(result.get('dns')).get('records',{}).get('TXT',[]) or []) if isinstance(x,dict)]
    tunnel=safe_sync('dns_tunneling', lambda ls,tx: dns_tunnel_score(ls,tx), labels, txt)
    takeover=safe_sync('subdomain_takeover', takeover_candidates, (as_dict(result.get('dns')).get('records',{}) or {}))
    c2_info=safe_sync('c2_infrastructure', analyze_c2, {**result,'fast_flux':{}})
    graph=safe_sync('graph', build_graph, {**result,'technology':result.get('technology') or []})
    risk=safe_sync('risk', score_risk, {**result,'url_forensics':url_info,'domain_overview':domain_info,'dns_posture':dns_info,'infrastructure':infra_info,'tls':tls_info,'http_posture':http_info,'reputation':rep_info,'graph':graph})
    ledger=safe_sync('evidence_ledger', build_ledger, result)
    geo_info=safe_sync('geography', build_geo, {**result,'tool_fabric':result.get('tool_fabric') or {}})
    banner_info=safe_sync('services_banners', build_banners, result)
    attack_surface=safe_sync('attack_surface', build_attack_surface, result)
    infrastructure_cluster=safe_sync('infrastructure_cluster', build_infrastructure_cluster, result)
    # Provider-backed public IP geolocation fallback. Only public IPs are sent to fixed geolocation providers.
    ip_geolocation=[]
    try:
        candidate_ips=[]
        for row in (attack_surface.get('a_records') or []):
            if isinstance(row,dict) and row.get('ip'): candidate_ips.append(str(row['ip']))
        for row in (result.get('ip_intelligence') or []):
            if isinstance(row,dict) and row.get('ip'): candidate_ips.append(str(row['ip']))
        candidate_ips=list(dict.fromkeys(candidate_ips))[:20]
        if candidate_ips:
            _emit('public_ip_geolocation','started',f'Country/city enrichment for {len(candidate_ips)} public IPs')
            import httpx
            async with httpx.AsyncClient(timeout=5,follow_redirects=True) as geo_client:
                ip_geolocation=await public_geo_lookup(geo_client,candidate_ips,limit=20)
            _emit('public_ip_geolocation','completed',f'{len(ip_geolocation)} provider geolocation observations')
        else:
            _emit('public_ip_geolocation','completed','No public IPs available for geolocation')
    except Exception as exc:
        errors.append({'stage':'public_ip_geolocation','error':str(exc)[:500],'recoverable':True})
        _emit('public_ip_geolocation','degraded',str(exc)[:180])
    dns_history=safe_sync('dns_temporal', summarize_dns_history, {**result,'passive_dns':result.get('passive_dns') or {}})
    cert_reuse=safe_sync('certificate_reuse', analyze_cert_reuse, result)
    asn_info=safe_sync('asn', analyze_asn, result)
    cloud_info=safe_sync('cloud', detect_cloud, result)
    osint_info=safe_sync('osint', build_osint_pivots, result)
    exposure_info=safe_sync('exposure_matrix', build_exposure_matrix, result)
    try:
        advanced_typos=advanced_typosquats(domain)
    except Exception as exc:
        advanced_typos=[]; errors.append({'stage':'advanced_typosquats','error':str(exc)[:500],'recoverable':True})
    calibration=safe_sync('risk_calibration', calibrate, risk)
    chain_summary=safe_sync('chain_summary', summarize_chain, result)
    watch=safe_sync('watch_plan', watch_plan, result)

    # Optional provider enrichment: every connector is independent so one missing credential never disables another.
    wappalyzer_info={"status":"not_configured","provider":"Wappalyzer","technologies":[],"employees":[]}
    linkedin_info={"status":"not_configured","provider":"LinkedIn","organization":None,"people":[]}
    ipinfo_rows=[]
    securitytrails_info={"status":"not_configured","provider":"SecurityTrails"}
    domaintools_info={"status":"not_configured","provider":"DomainTools","links":domaintools_web_links(domain) if domain else {}}
    domaintools_profile_info={"status":"not_configured","provider":"DomainTools"}
    domaintools_whois_info={"status":"not_configured","provider":"DomainTools"}
    if any([getattr(settings,'wappalyzer_api_key',''),getattr(settings,'linkedin_access_token',''),getattr(settings,'securitytrails_api_key',''),getattr(settings,'ipinfo_api_key','')]):
        try:
            import httpx
            async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
                if getattr(settings,'wappalyzer_api_key',''):
                    wappalyzer_info=await wappalyzer_lookup(client,(result.get('url') or (f"https://{domain}/" if domain else target)),getattr(settings,'wappalyzer_api_key',''))
                org_id=getattr(settings,'linkedin_organization_id','')
                if getattr(settings,'linkedin_access_token','') and org_id:
                    linkedin_info=await linkedin_org_lookup(client,org_id,getattr(settings,'linkedin_access_token',''),getattr(settings,'linkedin_version','202610'))
                if getattr(settings,'securitytrails_api_key','') and domain:
                    securitytrails_info=await securitytrails_domain_lookup(client,domain,getattr(settings,'securitytrails_api_key',''))
                if getattr(settings,'domaintools_api_key','') and domain:
                    _emit('domaintools_iris','started','DomainTools Iris Investigate')
                    domaintools_info=await domaintools_investigate(client,domain,getattr(settings,'domaintools_api_key',''))
                    domaintools_profile_info=await domaintools_profile(client,domain,getattr(settings,'domaintools_api_key',''))
                    domaintools_whois_info=await domaintools_whois(client,domain,getattr(settings,'domaintools_api_key',''))
                    domaintools_info['links']=domaintools_web_links(domain)
                    _emit('domaintools_iris','completed',str(domaintools_info.get('status')))
                if getattr(settings,'ipinfo_api_key',''):
                    net=result.get('network_associations') if isinstance(result.get('network_associations'),dict) else {}
                    for ip in list(net.get('current_ips') or [])[:30]:
                        row=await ipinfo_lookup(client,str(ip),getattr(settings,'ipinfo_api_key',''))
                        if isinstance(row,dict): ipinfo_rows.append(row)
        except Exception as exc:
            errors.append({'stage':'provider_enrichment','error':str(exc)[:500],'recoverable':True})

    workforce=build_workforce(wappalyzer=wappalyzer_info,linkedin=linkedin_info,domain=domain)
    domain_information=build_domain_information(domain, result.get('whois_rdap') if isinstance(result.get('whois_rdap'),dict) else {})
    if isinstance(domain_information.get('registrar'),dict):
        domain_information['registrar'] = {**domain_information['registrar'], 'normalized': normalize_entity(domain_information['registrar'])}
    domain_information['registrant'] = normalize_entity(domain_information.get('registrant'))
    domain_information['admin_contacts'] = [normalize_entity(x) for x in domain_information.get('admin_contacts',[]) if isinstance(x,dict)]
    domain_information['technical_contacts'] = [normalize_entity(x) for x in domain_information.get('technical_contacts',[]) if isinstance(x,dict)]
    domain_information['deep_field_matrix'] = build_domain_field_matrix(domain_information, result.get('whois_rdap') if isinstance(result.get('whois_rdap'),dict) else {}, result)
    dns_lookup_matrix=build_dns_lookup_matrix(result.get('dns'), domain)
    company_profile=build_company_profile(domain,wappalyzer_info,result.get('whois_rdap') if isinstance(result.get('whois_rdap'),dict) else {})
    if isinstance(company_profile,dict):
        company_profile['wappalyzer_locations']=(wappalyzer_info.get('company') or {}).get('locations') or [] if isinstance(wappalyzer_info,dict) else []
    branch_locations=build_branch_locations(company_profile, workforce, linkedin_info)
    ips=[str(x.get('ip')) for x in (attack_surface.get('a_records') or []) if isinstance(x,dict) and x.get('ip')]
    country_matrix=build_country_matrix({**result,'url_domain_vnext':{**(result.get('url_domain_vnext') or {}),'attack_surface':attack_surface}})
    service_matrix=build_service_matrix({**result,'url_domain_vnext':{**(result.get('url_domain_vnext') or {}),'attack_surface':attack_surface,'services_banners':banner_info}})
    if isinstance(service_matrix, dict) and isinstance(service_matrix.get('rows'), list):
        service_matrix['rows']=[normalize_service(x) for x in service_matrix['rows'] if isinstance(x,dict)]
    hosting_matrix=build_hosting_matrix({**result,'url_domain_vnext':{**(result.get('url_domain_vnext') or {}),'attack_surface':attack_surface}})
    osint_matrix=build_osint_matrix(domain,ips)
    advanced_osint=build_advanced_osint(result, domain, ips, graph)
    field_inventory=build_field_inventory(result)
    case_summary=build_case_summary({**result,'url_domain_vnext':{**(result.get('url_domain_vnext') or {}),'attack_surface':attack_surface}})
    search_plan=build_search_plan(domain,company_profile.get('company_name'))
    breach_matrix=build_breach_matrix({**(result.get('provider_results') if isinstance(result.get('provider_results'),dict) else {}), 'Have I Been Pwned': result.get('breach_intelligence')})
    third_party=build_third_party({**result,'wappalyzer':wappalyzer_info})
    security_stack = build_security_stack_observables({**result,'wappalyzer':wappalyzer_info})
    web_headers=(result.get('http') if isinstance(result.get('http'),dict) else {}).get('headers') or {}
    cdn_waf=detect_cdn_waf(web_headers)
    registration=registration_lifecycle(result.get('whois_rdap') if isinstance(result.get('whois_rdap'),dict) else {})
    dns_records=(result.get('dns') if isinstance(result.get('dns'),dict) else {}).get('records') or {}
    mail_security=analyze_mail_security(dns_records)
    hosting_summary=summarize_hosting(result.get('ip_intelligence') or [], asn_info if isinstance(asn_info,dict) else {})
    hostnames=[]
    for row in (result.get('dns') or {}).get('records',{}).get('CNAME',[]) if isinstance((result.get('dns') or {}).get('records',{}),dict) else []:
        if isinstance(row,dict) and row.get('value'): hostnames.append(str(row['value']))
    hosting_candidates=infer_from_names(hostnames)
    flux=assess_fast_flux((result.get('passive_dns') or {}).get('history_events') or [])
    c2_info=safe_sync('c2_infrastructure_final', analyze_c2, {**result,'fast_flux':flux})
    typo_family=typo_families(advanced_typos)
    dga_deep=[{'label':lab,**dga_detector(lab)} for lab in labels if lab]
    tunnel_deep=dns_tunnel_detector(labels,txt)
    if wappalyzer_info.get('status') == 'completed':
        company= wappalyzer_info.get('company') or {}
        if company.get('locations') and not geo_info.get('countries'):
            geo_info['company_locations']=company.get('locations')
        if wappalyzer_info.get('ip_country'):
            geo_info['ip_country']=wappalyzer_info.get('ip_country')
            try:
                geo_info=build_geo({**result,'wappalyzer':wappalyzer_info,'provider_results':result.get('provider_results') or {},'dnsdumpster':result.get('dnsdumpster') or {}})
            except Exception:
                pass
    for loc in ipinfo_rows:
        if loc.get('lat') is not None and loc.get('lon') is not None:
            geo_info.setdefault('map_points',[]).append({'lat':loc['lat'],'lon':loc['lon'],'country':loc.get('country'),'country_code':loc.get('country'),'city':loc.get('city'),'ip':loc.get('ip'),'organization':loc.get('org'),'source':'IPinfo','precision':'provider-coordinate'})
        if loc.get('country'):
            geo_info.setdefault('countries',[]).append({'country':loc.get('country'),'count':1})

    # Rebuild geography once attack-surface rows and provider IP observations are known.
    try:
        geo_info = safe_sync('geography_final', build_geo, {**result, 'wappalyzer': wappalyzer_info, 'provider_results': result.get('provider_results') or {}, 'dnsdumpster': result.get('dnsdumpster') or {}, 'url_domain_vnext': {**(result.get('url_domain_vnext') or {}), 'attack_surface': attack_surface}, 'ip_geolocation': ipinfo_rows})
    except Exception:
        pass

    # Promote normalized attack-surface rows into the case graph without inventing observations.
    try:
        g=graph if isinstance(graph,dict) else {'nodes':[],'edges':[],'node_count':0,'edge_count':0}
        nodes=list(g.get('nodes') or []); edges=list(g.get('edges') or [])
        ids={str(n.get('id')) for n in nodes if isinstance(n,dict) and n.get('id')}
        edge_keys={(str(e.get('source')),str(e.get('target')),str(e.get('relation'))) for e in edges if isinstance(e,dict)}
        root_id=f'domain:{domain}'
        if root_id not in ids:
            nodes.append({'id':root_id,'kind':'domain','label':domain,'meta':{}}); ids.add(root_id)
        for row in (attack_surface.get('a_records') or [])[:1000]:
            host=str(row.get('host') or '').strip(); ip=str(row.get('ip') or '').strip()
            if not host or not ip: continue
            hid=f'host:{host}'; iid=f'ip:{ip}'
            if hid not in ids: nodes.append({'id':hid,'kind':'host','label':host,'meta':{'source':row.get('source') or 'provider-returned'}}); ids.add(hid)
            if iid not in ids: nodes.append({'id':iid,'kind':'ip','label':ip,'meta':{'country':row.get('country'),'asn':row.get('asn'),'source':'DNSDumpster'}}); ids.add(iid)
            for a,b,rel in ((root_id,hid,'discovers'),(hid,iid,'resolves-to')):
                if (a,b,rel) not in edge_keys:
                    edges.append({'source':a,'target':b,'relation':rel,'confidence':88,'source':row.get('source') or 'provider-returned'}); edge_keys.add((a,b,rel))
            if row.get('asn'):
                aid=f'asn:{row.get("asn")}';
                if aid not in ids: nodes.append({'id':aid,'kind':'asn','label':f'AS{row.get("asn")}','meta':{'name':row.get('asn_name'),'range':row.get('asn_range')}}); ids.add(aid)
                if (iid,aid,'announced-by') not in edge_keys:
                    edges.append({'source':iid,'target':aid,'relation':'announced-by','confidence':82,'source':row.get('source') or 'provider-returned'}); edge_keys.add((iid,aid,'announced-by'))
            for service in (row.get('open_services') or [])[:30]:
                sid=f'service:{ip}:{service}'
                if sid not in ids: nodes.append({'id':sid,'kind':'service','label':str(service),'meta':{'ip':ip}}); ids.add(sid)
                if (iid,sid,'exposes') not in edge_keys:
                    edges.append({'source':iid,'target':sid,'relation':'exposes','confidence':78,'source':row.get('source') or 'provider-returned'}); edge_keys.add((iid,sid,'exposes'))
        graph={'nodes':nodes[:3000],'edges':edges[:8000],'node_count':len(nodes),'edge_count':len(edges)}
    except Exception as exc:
        errors.append({'stage':'attack_surface_graph','error':str(exc)[:500],'recoverable':True})

    geo_info.setdefault('country_layers', world_layers((geo_info.get('provider_rows') or []) + ip_geolocation + (attack_surface.get('a_records') or [])))
    live_map=build_live_map_contract(geo_info, branch_locations)
    dnssec_observed = ((result.get('dns') or {}).get('dnssec') if isinstance(result.get('dns'),dict) else {}) or {}
    earth_observatory=build_earth_observatory(result, geo_info, branch_locations, attack_surface, result.get('dns') if isinstance(result.get('dns'),dict) else {}, result.get('whois_rdap') if isinstance(result.get('whois_rdap'),dict) else {}, ct_info, result.get('http') if isinstance(result.get('http'),dict) else {}, result.get('tls') if isinstance(result.get('tls'),dict) else {}, dnssec_observed, mail_security, cdn_waf, asn_info, registration, hosting_summary, security_stack, dns_history, company_profile)
    domain_health_recon=build_domain_health_recon(result, attack_surface=attack_surface, dns=result.get('dns') if isinstance(result.get('dns'),dict) else {}, whois=result.get('whois_rdap') if isinstance(result.get('whois_rdap'),dict) else {}, ct=ct_info, http=result.get('http') if isinstance(result.get('http'),dict) else {}, tls=result.get('tls') if isinstance(result.get('tls'),dict) else {}, dnssec=dnssec_observed, mail=mail_security, cdn=cdn_waf, asn=asn_info, registration=registration, hosting=hosting_summary, security_stack=security_stack, pdns=dns_history, branches=branch_locations, geo=geo_info, cert_reuse=cert_reuse, technology=result.get('technology') or result.get('wappalyzer') or [], breach=result.get('breach_intelligence') if isinstance(result.get('breach_intelligence'),dict) else {}, reputation=rep_info)
    registrant_intelligence=build_registrant_intelligence(domain_information, result.get('whois_rdap') if isinstance(result.get('whois_rdap'),dict) else {}, company_profile, attack_surface, graph, ct_info)
    recon_investigation_plan=build_recon_investigation_plan(domain, profile=str(result.get('investigation_profile') or 'deep'), explicit_scope=bool(result.get('authorized_scope')), internal_scope=bool(result.get('internal_scope')))
    geo_info['ip_observations'] = len(ip_geolocation)
    analyst_matrix = build_analyst_matrix(result, {'geo_intelligence':geo_info,'attack_surface':attack_surface,'osint_deep':osint_info,'graph':graph,'evidence_ledger':ledger,'c2_intelligence':c2_info})
    deep_reasoning=safe_sync('deep_reasoning', build_deep_reasoning, {**result,'risk':risk,'workforce':workforce,'third_party_services':third_party})
    ai_plan=safe_sync('ai_task_plan', task_plan, {**result,'risk':risk})
    # Embedded/silent AI surface: deterministic evidence-grounded analyst state. The UI presents this across modules, not as a standalone AI page.
    try:
        health_cov=(domain_health_recon.get('summary') or {}).get('coverage_percent',0)
        silent_ai={'status':'active','mode':'evidence-grounded-silent-analyst','coverage_percent':health_cov,'risk_score':risk.get('score',risk.get('risk_score',0)) if isinstance(risk,dict) else 0,
                   'signals':len((risk.get('signals') or []) if isinstance(risk,dict) else []),'next_pivots':len((advanced_osint.get('pivots') or [])) if isinstance(advanced_osint,dict) else 0,
                   'policy':'No invented observations; conclusions link to case evidence and provider state.'}
    except Exception:
        silent_ai={'status':'degraded','mode':'evidence-grounded-silent-analyst','policy':'No invented observations.'}
    deep={
      'version':'DOMINUS-ULTIMATE-V29','architecture_layers':12,
      'url':url_info,'domain':domain_info,'dns':dns_info,'rdap_lifecycle':rdap_info,'certificate_transparency':ct_info,
      'infrastructure':infra_info,'http':http_info,'tls':tls_info,'reputation_fusion':rep_info,'breach_exposure':breach_info,
      'detections':{'homograph':safe_sync('homograph',homograph_assessment,domain),'typosquatting':typo,'dga':dga,'dns_tunneling':tunnel,'subdomain_takeover':takeover},
      'c2_intelligence':c2_info,'infrastructure_cluster':infrastructure_cluster,
      'graph':graph,'risk':risk,'risk_calibration':calibration,'evidence_ledger':ledger,'chain_summary':chain_summary,'domain_health_recon':domain_health_recon,'registrant_intelligence':registrant_intelligence,'recon_investigation_plan':recon_investigation_plan,'recon_tool_catalog':TOOL_CATALOG,
      'pivots':suggest(result),'osint_deep':osint_info,'osint_matrix':osint_matrix,'advanced_osint':advanced_osint,'ai_task_plan':ai_plan,'deep_reasoning':deep_reasoning,'silent_ai':silent_ai,
      'monitoring':monitoring_manifest(),'watch_plan':watch,'geo_intelligence':geo_info,'live_map':live_map,'earth_observatory':earth_observatory,'branch_locations':branch_locations,'domain_information':domain_information,'dns_lookup_matrix':dns_lookup_matrix,'analyst_matrix':analyst_matrix,'services_banners':banner_info,'attack_surface':attack_surface,
      'dns_temporal':dns_history,'mail_security':mail_security,'registration_lifecycle':registration,'cdn_waf':cdn_waf,'hosting_summary':hosting_summary,'hosting_candidates':hosting_candidates,'fast_flux':flux,'typosquat_families':typo_family,'dga_deep':dga_deep,'dns_tunnel_deep':tunnel_deep,'certificate_reuse':cert_reuse,'asn_intelligence':asn_info,'cloud_attribution':cloud_info,
      'exposure_matrix':exposure_info,'advanced_typosquats':advanced_typos,'graph_layout_contract':graph_layout_contract(),
      'pipeline_stages':stage_plan(),'investigation_profile':str(result.get('investigation_profile') or 'deep'),'collection_plan':build_collection_plan(str(result.get('investigation_profile') or 'deep'), result.get('provider_results') if isinstance(result.get('provider_results'),dict) else {}),'collection_matrix':{'core_dns': 'collected via resolver stage','attack_surface':'DNSDumpster preferred with DNS-over-HTTPS fallback','geo':'provider-backed only','services':'provider/banner observations only','breach':'authorized provider-dependent'},'capability_catalog_count':sum(x[1] for x in __import__('phishhunter.url_domain_analyst.connectors.capability_registry',fromlist=['CAPABILITY_CATEGORIES']).CAPABILITY_CATEGORIES),
      'wappalyzer':wappalyzer_info,'linkedin':linkedin_info,'workforce_intelligence':workforce,'company_profile':company_profile,'branch_locations':branch_locations,'search_plan':search_plan,'breach_matrix':breach_matrix,'domaintools':domaintools_info,'domaintools_profile':domaintools_profile_info,'domaintools_whois':domaintools_whois_info,
      'third_party_services':third_party,'ip_geolocation':ipinfo_rows + ip_geolocation,'securitytrails':securitytrails_info,'security_stack_observables':security_stack,'provider_error_ledger':errors,
      'safety':{'passive_first':True,'no_arbitrary_shell':True,'no_dynamic_js_execution':True,'no_direct_dark_web_crawl':True,'provider_provenance_required':True,'no_linkedin_scraping':True},
    }
    return deep

def domain_info_from_result(result:dict)->str:
    return str(result.get('registered_domain') or result.get('target') or '')
