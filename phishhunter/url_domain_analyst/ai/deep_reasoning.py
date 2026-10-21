from __future__ import annotations
from collections import defaultdict

def build(result:dict)->dict:
    risk=result.get('risk') or {}
    sigs=risk.get('signals') or []
    dimensions=['structure','domain','dns','infrastructure','certificate','content','visual','reputation','behavioral','correlation']
    observed=[]; unknown=[]; hypotheses=[]
    for s in sigs[:20]:
        observed.append({'signal':s.get('name'),'weight':s.get('weight'),'reason':s.get('reason')})
    if not result.get('passive_dns',{}).get('history_events'):
        unknown.append('Historical passive-DNS coverage is unavailable without a provider dataset.')
    if not (result.get('geo_intelligence') or {}).get('map_points'):
        unknown.append('No provider-returned coordinates are available for the infrastructure map.')
    if (result.get('breach_intelligence') or {}).get('status') not in ('completed','no_results'):
        unknown.append('Breach status is provider-dependent and has not been confirmed for this target.')
    if result.get('domain_overview',{}).get('punycode') or result.get('domain_overview',{}).get('mixed_script'):
        hypotheses.append({'type':'identity-confusion','confidence':'medium','reason':'Internationalized or mixed-script domain characteristics require analyst verification.'})
    if (result.get('http') or {}).get('redirect_count',0) > 2:
        hypotheses.append({'type':'redirect-obfuscation','confidence':'medium','reason':'Multiple redirect hops increase the need to inspect each intermediary.'})
    return {
        'mode':'deep-evidence-reasoning',
        'status':'ready',
        'dimensions':dimensions,
        'observed_signals':observed,
        'hypotheses':hypotheses,
        'unknowns':unknown,
        'recommended_depth':['registration','dns','historical_dns','ct','subdomains','ip_network','tls','http','redirects','technology','reputation','breach','osint','correlation','evidence'],
        'guardrail':'The reasoning layer does not invent provider evidence, identity, compromise, or threat-actor attribution.'
    }
