from __future__ import annotations

def plan(result:dict)->dict:
    target=result.get('domain') or result.get('target')
    return {'watchable':True,'target':target,'triggers':['new-subdomain','DNS-change','certificate-issued','certificate-changed','WHOIS-change','HTTP-header-change','content-drift','reputation-change','breach-provider-change','brand-lookalike-seen'], 'cadence_options':['on-demand','hourly','daily','weekly','adaptive-risk']}
