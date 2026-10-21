from __future__ import annotations
from collections import Counter, defaultdict
from typing import Any

def build(result: dict[str, Any]) -> dict[str, Any]:
    rows=[]
    providers=result.get('provider_results') if isinstance(result.get('provider_results'),dict) else {}
    for provider,payload in providers.items():
        if payload in (None,{},[]): continue
        if isinstance(payload,dict):
            for key in ('results','data','matches','records','indicators'):
                values=payload.get(key)
                if isinstance(values,list):
                    for item in values[:500]:
                        if isinstance(item,dict): rows.append({'provider':provider,**{k:item.get(k) for k in ('ip','domain','host','url','asn','country','classification','category','threat') if item.get(k) is not None}})
    by_ip=defaultdict(set); by_asn=defaultdict(set); by_country=Counter()
    for r in rows:
        if r.get('ip'): by_ip[str(r['ip'])].add(str(r.get('provider')))
        if r.get('asn'): by_asn[str(r['asn'])].add(str(r.get('provider')))
        if r.get('country'): by_country[str(r['country'])]+=1
    return {'status':'complete' if rows else 'provider-dependent','provider_observations':rows[:1000], 'shared_ips':[{'ip':k,'providers':sorted(v)} for k,v in by_ip.items() if len(v)>1][:200], 'shared_asns':[{'asn':k,'providers':sorted(v)} for k,v in by_asn.items() if len(v)>1][:200], 'countries':[{'country':k,'count':v} for k,v in by_country.most_common(50)]}
