from __future__ import annotations
from importlib import import_module
import asyncio
from typing import Any
from urllib.parse import urlparse
from .deep_intelligence.normalization import normalize_target

_LEGACY_MODULE='phishhunter.analyzers.unified_url_domain'
_LEGACY_FUNCTION='analyze_url_domain'

async def _legacy(target:str,*args:Any,**kwargs:Any)->dict:
    fn=getattr(import_module(_LEGACY_MODULE),_LEGACY_FUNCTION)
    try:
        return await fn(target,*args,**kwargs)
    except TypeError as exc:
        # Backward compatibility for legacy analyzers that do not accept newer profile kwargs.
        if "profile" in kwargs and "unexpected keyword argument 'profile'" in str(exc):
            fallback_kwargs=dict(kwargs)
            fallback_kwargs.pop("profile",None)
            return await fn(target,*args,**fallback_kwargs)
        raise

def _fallback_result(target: str, error: Exception | None = None) -> dict[str, Any]:
    raw=str(target or '').strip()
    parsed=urlparse(raw if '://' in raw else f'https://{raw}')
    host=(parsed.hostname or raw).rstrip('.').lower()
    registered='.'.join(host.split('.')[-2:]) if host.count('.')>=1 else host
    return {
        'target':raw,'target_type':'url' if parsed.scheme in {'http','https'} else 'domain',
        'url': raw if parsed.scheme in {'http','https'} else f'https://{host}/',
        'domain':host,'registered_domain':registered,'domain_overview':{'domain':host,'registered_domain':registered},
        'url_forensics':{},'whois_rdap':{},'dns':{'records':{},'reverse_dns':{}},'dns_authentication':{},
        'dns_posture':{},'network_associations':{'current_ips':[],'mx_hosts':[],'name_servers':[]},'ip_intelligence':[],
        'certificate_transparency':{},'certificate_posture':{},'http':{'status':'not_collected'},'http_posture':{},'tls':{'status':'not_collected'},
        'security_headers':{},'technology':[],'reputation':{'signals':[],'provider_states':{}},'risk_score':0,
        'verdict':'unknown','provider_results':{},'breach_intelligence':{'status':'not_collected','records':[]},
        'breach_posture':{'direct_dark_web_crawl':False},'dnsdumpster':{'status':'not_collected','records':[]},
        'passive_dns':{'status':'provider-required'},'availability':{'dns_resolves':False,'http_state':'not_collected'},
        'traffic':{'status':'provider-dependent'},'iocs':{},'mitre_techniques':[],'risk':{'score':0,'verdict':'unknown','signals':[]},
        'timeline':[],'evidence':[],'graph':{'nodes':[],'edges':[],'node_count':0,'edge_count':0},'graph_summary':{},
        'investigation_pivots':[],'osint_pivots':[],'tool_fabric':{},'investigation_matrix':[],
        'collection':{'passive_first':True},'notes':['Base collector failed; vNext continued with safe empty/provider-dependent fields.'],
        'base_collection_error':str(error)[:500] if error else None,
        'url_domain_vnext': {
            'version':'DOMINUS-ULTIMATE-V29','geo_intelligence':{'countries':[],'hosting_networks':[],'map_points':[]},
            'workforce_intelligence':{'company_name':None,'industry':None,'company_type':None,'founded':None,'employee_size_range':None,'linkedin_urls':[],'employee_rows':[],'employee_observation_count':0},
            'third_party_services':[],'security_stack_observables':[],'provider_error_ledger':[]
        },
    }

async def analyze(target:str,*args:Any,**kwargs:Any)->dict:
    """Run the stable analyzer and continue with vNext even when a provider or legacy path fails."""
    try:
        normalized=normalize_target(target)
        target=normalized["raw"]
    except Exception as exc:
        return _fallback_result(target, exc)
    profile=str(kwargs.get("profile") or "deep").lower()
    progress_cb = kwargs.get("progress_cb")
    if "progress_cb" in kwargs:
        kwargs = dict(kwargs)
        kwargs.pop("progress_cb", None)
    legacy_budget={"quick":12.0,"deep":24.0,"forensic":35.0}.get(profile,24.0)
    try:
        result=await asyncio.wait_for(_legacy(target,*args,**kwargs), timeout=legacy_budget)
        if not isinstance(result,dict):
            raise TypeError(f'legacy analyzer returned {type(result).__name__}, expected dict')
        base_error=None
    except Exception as exc:
        result=_fallback_result(target,exc)
        base_error=exc
    from .orchestration.deep_pipeline import augment
    try:
        result['url_domain_vnext']=await augment(result,target,progress_cb=progress_cb)
        status='completed_with_base_fallback' if base_error else 'completed'
    except Exception as exc:
        result['url_domain_vnext']={'version':'DOMINUS-ULTIMATE-V29','provider_error_ledger':[{'stage':'pipeline','error':str(exc)[:500],'recoverable':True}]}
        status='completed_partial'
    result['url_domain_vnext_status']={'status':status,'version':'28.0','source':'phishhunter.url_domain_analyst','profile': kwargs.get('profile','deep')}
    result.setdefault('investigation_profile', kwargs.get('profile','deep'))
    return result
