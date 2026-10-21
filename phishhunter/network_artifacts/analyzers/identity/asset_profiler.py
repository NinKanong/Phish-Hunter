from __future__ import annotations
from collections import Counter,defaultdict

def profile(events):
    assets=defaultdict(lambda:{'peers':set(),'ports':Counter(),'protocols':Counter(),'bytes':0})
    for e in events:
        s=e.get('src_ip');d=e.get('dst_ip');
        if s:
            a=assets[s]; a['peers'].add(d); a['ports'][str(e.get('dst_port'))]+=1; a['protocols'][str(e.get('protocol') or 'unknown')]+=1; a['bytes']+=int(e.get('bytes') or 0)
    return [{'ip':ip,'peer_count':len(v['peers']),'top_ports':dict(v['ports'].most_common(20)),'protocols':dict(v['protocols']),'bytes':v['bytes']} for ip,v in sorted(assets.items(),key=lambda x:-x[1]['bytes'])[:500]]
