from __future__ import annotations
from collections import Counter
from typing import Any

def analyze(result:dict[str,Any])->dict[str,Any]:
    rows=[]
    for r in ((result.get('provider_results') or {}).get('AbuseIPDB') or {}).get('results') or []:
        rows.append({'ip':r.get('ip'),'asn':r.get('asn'),'isp':r.get('isp'),'country':r.get('countryCode'),'domain':r.get('domain'),'reports':r.get('totalReports')})
    asns=Counter(str(r.get('asn')) for r in rows if r.get('asn'))
    return {'rows':rows,'asn_distribution':[{'asn':k,'count':v} for k,v in asns.most_common()], 'status':'observed' if rows else 'provider-dependent'}
