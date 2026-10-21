from __future__ import annotations
from collections import defaultdict

def detect(events):
    ports=defaultdict(set); targets=defaultdict(set)
    for e in events:
        s=e.get('src_ip'); d=e.get('dst_ip'); p=e.get('dst_port')
        if s and d: targets[s].add(d)
        if s and p: ports[s].add(p)
    out=[]
    for src in set(ports)|set(targets):
        if len(ports[src])>=20 or len(targets[src])>=30:
            out.append({'source':src,'unique_ports':len(ports[src]),'unique_targets':len(targets[src]),'confidence':50,'reason':'broad destination/port fan-out'})
    return sorted(out,key=lambda x:-(x['unique_ports']+x['unique_targets']))[:200]
