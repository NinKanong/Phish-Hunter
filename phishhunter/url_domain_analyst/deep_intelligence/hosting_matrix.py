from __future__ import annotations
from collections import Counter

def build(result:dict)->dict:
    v=result.get('url_domain_vnext') if isinstance(result.get('url_domain_vnext'),dict) else {}
    s=v.get('attack_surface') if isinstance(v.get('attack_surface'),dict) else {}
    rows=[x for x in (s.get('a_records') or []) if isinstance(x,dict)]
    asn=Counter(str(x.get('asn') or 'Unknown') for x in rows)
    org=Counter(str(x.get('asn_name') or 'Unknown') for x in rows)
    return {'asn':[{'name':k,'count':v} for k,v in asn.most_common(100)],'organizations':[{'name':k,'count':v} for k,v in org.most_common(100)],'rows':rows[:10000]}
