from __future__ import annotations
from collections import Counter,defaultdict

def identify(events):
    hosts=defaultdict(lambda:{'protocols':Counter(),'hostnames':set(),'user_agents':set(),'ports':Counter()})
    for e in events:
        for ip in (e.get('src_ip'),e.get('dst_ip')):
            if not ip:continue
            h=hosts[ip]; h['protocols'][str(e.get('protocol') or 'unknown')]+=1
            if e.get('hostname'):h['hostnames'].add(str(e['hostname']))
            raw=e.get('raw') or {}; http=raw.get('http') or {}
            if http.get('user_agent'):h['user_agents'].add(http['user_agent'])
            if e.get('dst_port'):h['ports'][str(e['dst_port'])]+=1
    return [{'ip':ip,'hostnames':sorted(v['hostnames'])[:50],'user_agents':sorted(v['user_agents'])[:20],'protocols':dict(v['protocols']),'ports':dict(v['ports'].most_common(30))} for ip,v in list(hosts.items())[:500]]
