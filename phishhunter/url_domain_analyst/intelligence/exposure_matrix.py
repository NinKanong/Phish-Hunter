from __future__ import annotations

def build(result:dict)->dict:
    p=result.get('provider_results') or {}
    breach=result.get('breach_intelligence') or {}
    rows=[]
    for name,val in sorted(p.items()):
        rows.append({'provider':name,'state':val.get('status'),'hit_count':len(val.get('matches') or val.get('results') or []) if isinstance(val,dict) else None})
    rows.append({'provider':breach.get('provider','Have I Been Pwned'),'state':breach.get('status'),'hit_count':breach.get('breached_identity_count',0)})
    return {'providers':rows,'confirmed_hits':sum(int(x.get('hit_count') or 0) for x in rows if x.get('state') in ('completed','live-configured')),'unknowns':[x['provider'] for x in rows if x.get('state') not in ('completed','live-configured','no_results')]}
