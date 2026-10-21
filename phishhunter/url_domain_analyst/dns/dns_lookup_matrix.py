from __future__ import annotations
from typing import Any

RECORDS=('A','AAAA','CNAME','MX','NS','TXT','SOA','CAA','SRV','NAPTR','DNSKEY','DS','RRSIG','TLSA','SSHFP')

def build(dns:dict|None, domain:str='')->dict[str,Any]:
    d=dns if isinstance(dns,dict) else {}; records=d.get('records') if isinstance(d.get('records'),dict) else {}
    rows=[]
    for rtype in RECORDS:
        values=records.get(rtype) or []
        if not isinstance(values,list): values=[]
        rows.append({'type':rtype,'count':len(values),'records':values,'observed':bool(values)})
    return {'domain':domain,'resolver':d.get('resolver'),'queried_at':d.get('queried_at'),'record_types':rows,
            'total_records':sum(x['count'] for x in rows),'reverse_dns':d.get('reverse_dns') or {},
            'lookup_scope':'Current DNS resolver observations. Historical DNS requires a passive-DNS provider.'}
