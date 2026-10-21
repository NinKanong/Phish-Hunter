from __future__ import annotations
import ipaddress
from collections import Counter

def classify(events):
    external=Counter()
    targets={}
    for e in events:
        s,d=e.get('src_ip'),e.get('dst_ip')
        try: external_ok=bool(s and ipaddress.ip_address(s).is_global and d and ipaddress.ip_address(d).is_private)
        except Exception: external_ok=False
        if external_ok:
            external[s]+=1; targets.setdefault(s,set()).add(d)
    return [{'source_ip':ip,'connections':n,'internal_targets':sorted(targets[ip])[:100],'assessment':'external-source candidate','confidence':'low-to-medium'} for ip,n in external.most_common(200)]
