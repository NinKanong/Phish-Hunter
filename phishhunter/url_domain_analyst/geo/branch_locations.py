from __future__ import annotations
from typing import Any


def _one(x:Any, source:str, kind:str='company') -> dict[str,Any]|None:
    if isinstance(x,str):
        s=x.strip()
        return {'name':s,'address':s,'city':None,'region':None,'country':None,'country_code':None,'lat':None,'lon':None,'source':source,'kind':kind} if s else None
    if not isinstance(x,dict): return None
    return {
        'name':x.get('name') or x.get('title') or x.get('label') or x.get('city') or x.get('address'),
        'address':x.get('address') or x.get('street') or x.get('formatted_address'),
        'city':x.get('city'), 'region':x.get('region') or x.get('state'),
        'country':x.get('country') or x.get('countryName'), 'country_code':x.get('country_code') or x.get('countryCode'),
        'lat':x.get('lat') or x.get('latitude'), 'lon':x.get('lon') or x.get('lng') or x.get('longitude'),
        'source':source, 'kind':x.get('kind') or kind,
        'organization':x.get('organization'), 'url':x.get('url') or x.get('website'),
    }


def build(company_profile:dict|None=None, workforce:dict|None=None, linkedin:dict|None=None) -> dict:
    rows=[]
    sources=[
        ('company_profile', (company_profile or {}).get('locations') if isinstance(company_profile,dict) else []),
        ('wappalyzer', (company_profile or {}).get('wappalyzer_locations') if isinstance(company_profile,dict) else []),
        ('linkedin', ((linkedin or {}).get('organization') or {}).get('locations') if isinstance(linkedin,dict) and isinstance((linkedin or {}).get('organization'),dict) else []),
    ]
    for source,items in sources:
        if not isinstance(items,list): items=[items] if items else []
        for item in items:
            row=_one(item,source)
            if row: rows.append(row)
    dedup=[]; seen=set()
    for row in rows:
        key=(str(row.get('name') or ''),str(row.get('address') or ''),str(row.get('city') or ''),str(row.get('country') or ''))
        if key in seen: continue
        seen.add(key); dedup.append(row)
    return {'locations':dedup[:1000], 'count':len(dedup), 'basis':'provider-backed corporate/workforce location data only',
            'warning':'IP geolocation is not used to invent company branches. Branch locations require provider-backed corporate evidence.'}
