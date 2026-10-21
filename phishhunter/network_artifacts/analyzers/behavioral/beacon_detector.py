from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from statistics import mean,pstdev

def detect(events):
    groups=defaultdict(list)
    for e in events:
        key=(e.get('src_ip'),e.get('dst_ip'),e.get('dst_port'),e.get('protocol'))
        try: groups[key].append(datetime.fromisoformat(str(e.get('timestamp')).replace('Z','+00:00')).timestamp())
        except Exception: pass
    out=[]
    for key,times in groups.items():
        times=sorted(set(times))
        if len(times)<5:continue
        intervals=[b-a for a,b in zip(times,times[1:]) if b>a]
        if len(intervals)<4:continue
        avg=mean(intervals); cv=pstdev(intervals)/avg if avg else 99
        if cv<=0.35:
            out.append({'source':key[0],'destination':key[1],'port':key[2],'protocol':key[3],'observations':len(times),'mean_interval_seconds':round(avg,3),'coefficient_variation':round(cv,4),'confidence':round(max(0,min(100,90-cv*150)),1),'reason':'regular repeated communication interval'})
    return out[:500]
