from __future__ import annotations

def build_findings(deep:dict)->list[dict]:
    f=[]
    u=deep.get('url',{}); d=deep.get('domain',{}); det=deep.get('detections',{}); rep=deep.get('reputation_fusion',{})
    if u.get('obfuscation',{}).get('techniques'): f.append({'severity':'medium','title':'URL obfuscation indicators','evidence':u['obfuscation']['techniques'],'type':'observed-or-derived'})
    if d.get('mixed_scripts') or d.get('invisible_chars'): f.append({'severity':'high','title':'Unicode/IDN anomaly','evidence':{'mixed_scripts':d.get('mixed_scripts'),'invisible_chars':d.get('invisible_chars')},'type':'heuristic'})
    if rep.get('positive_count'): f.append({'severity':'medium','title':'Reputation provider signal','evidence':rep,'type':'provider-signal'})
    for item in det.get('subdomain_takeover',[]): f.append({'severity':'high','title':'Potential subdomain takeover candidate','evidence':item,'type':'requires-verification'})
    return f
