from __future__ import annotations
from collections import Counter

def build(result:dict)->dict:
    v=result.get('url_domain_vnext') if isinstance(result.get('url_domain_vnext'),dict) else {}
    sb=v.get('services_banners') if isinstance(v.get('services_banners'),dict) else {}
    surface=v.get('attack_surface') if isinstance(v.get('attack_surface'),dict) else {}
    rows=[x for x in (sb.get('rows') or surface.get('services') or []) if isinstance(x,dict)]
    counts=Counter((str(x.get('product') or x.get('service') or x.get('server') or 'Unknown').strip() or 'Unknown') for x in rows)
    return {'rows':rows[:10000], 'products':[{'name':k,'count':v} for k,v in counts.most_common(100)], 'observed_only':True}
