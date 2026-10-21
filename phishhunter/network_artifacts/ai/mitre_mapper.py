from __future__ import annotations
from typing import Any

PORTS={22:('T1021.004','SSH'),3389:('T1021.001','RDP'),445:('T1021.002','SMB/Windows Admin Shares'),5985:('T1021.006','Windows Remote Management'),5986:('T1021.006','Windows Remote Management'),135:('T1047','Windows Management Instrumentation'),139:('T1021.002','SMB/Windows Admin Shares'),1433:('T1021','Remote Services')}

def map_events(events:list[dict[str,Any]], findings:list[dict[str,Any]]|None=None)->list[dict[str,Any]]:
    out=[]; seen=set()
    for e in events:
        p=e.get('dst_port')
        if p in PORTS:
            tid,name=PORTS[p]; key=(tid,e.get('src_ip'),e.get('dst_ip'),p)
            if key in seen:continue
            seen.add(key); out.append({'technique_id':tid,'name':name,'tactic':'lateral-movement' if tid.startswith('T1021') else 'execution','source_event':{'timestamp':e.get('timestamp'),'src_ip':e.get('src_ip'),'dst_ip':e.get('dst_ip'),'dst_port':p},'confidence':55,'basis':'Observed network service port; technique mapping is a candidate, not proof of technique execution.'})
    return out[:1000]
