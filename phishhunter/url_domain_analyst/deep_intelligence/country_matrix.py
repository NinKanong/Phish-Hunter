from __future__ import annotations
from collections import Counter

def build(result:dict)->dict:
    a=[]
    v=result.get('url_domain_vnext') if isinstance(result.get('url_domain_vnext'),dict) else {}
    s=v.get('attack_surface') if isinstance(v.get('attack_surface'),dict) else {}
    a.extend(x for x in (s.get('a_records') or []) if isinstance(x,dict))
    rows=[]; c=Counter();
    for x in a:
        country=str(x.get('country') or 'Unknown').strip() or 'Unknown'; c[country]+=1
        rows.append({'country':country,'country_code':x.get('country_code'),'host':x.get('host'),'ip':x.get('ip'),'asn':x.get('asn'),'organization':x.get('asn_name'),'ptr':x.get('ptr'),'source':x.get('source')})
    return {'countries':[{'country':k,'count':v} for k,v in c.most_common()], 'observations':rows[:10000], 'location_basis':'provider-returned location only'}
