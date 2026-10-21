from __future__ import annotations
from collections import defaultdict

def detect(events):
    grouped=defaultdict(lambda:{'bytes':0,'events':0,'destinations':set()})
    for e in events:
        if e.get('src_ip') and e.get('dst_ip'):
            k=(e['src_ip'],e['dst_ip']); grouped[k]['bytes']+=int(e.get('bytes') or 0); grouped[k]['events']+=1; grouped[k]['destinations'].add(e['dst_ip'])
    out=[]
    for (src,dst),v in grouped.items():
        if v['bytes']>=10_000_000 and v['events']>=5:
            out.append({'source':src,'destination':dst,'bytes':v['bytes'],'events':v['events'],'confidence':45,'reason':'high-volume repeated transfer candidate'})
    return sorted(out,key=lambda x:-x['bytes'])[:200]
