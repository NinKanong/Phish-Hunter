from __future__ import annotations
from typing import Any

def summarize(result:dict[str,Any])->dict[str,Any]:
    pdns=result.get('passive_dns') or {}
    hist=[]
    for key,label in [('historical_ip_associations','A/AAAA'),('historical_ns_associations','NS'),('historical_mx_associations','MX')]:
        for row in pdns.get(key) or []:
            hist.append({'dimension':label,**(row if isinstance(row,dict) else {'value':row})})
    return {
        'status':pdns.get('status','provider-dependent'),
        'history_events':hist[:1000],
        'ip_migration_count':len({str(x.get('value')) for x in hist if isinstance(x,dict) and x.get('dimension')=='A/AAAA' and x.get('value')}),
        'ns_change_count':len([x for x in hist if isinstance(x,dict) and x.get('dimension')=='NS']),
        'mx_change_count':len([x for x in hist if isinstance(x,dict) and x.get('dimension')=='MX']),
        'note':'Historical conclusions require passive-DNS observations with timestamps; current DNS is not treated as historical.'
    }
