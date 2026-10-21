from __future__ import annotations
from typing import Any

PROVIDERS=['Have I Been Pwned','IntelX','DeHashed','Hudson Rock','SpyCloud','Constella','LeakIX','MISP/OpenCTI']

def build(provider_results:dict[str,Any]|None=None)->dict[str,Any]:
    p=provider_results if isinstance(provider_results,dict) else {}
    rows=[]
    for name in PROVIDERS:
        value=p.get(name)
        if isinstance(value,dict):
            state=value.get('status','unknown')
            hits=len(value.get('records') or value.get('results') or value.get('matches') or [])
        else:
            state='not-configured'; hits=0
        rows.append({'provider':name,'status':state,'hit_count':hits})
    return {'rows':rows,'configured_count':sum(r['status'] in ('completed','live-configured') for r in rows),'positive_providers':[r['provider'] for r in rows if r['hit_count']>0], 'direct_dark_web_crawl':False}
