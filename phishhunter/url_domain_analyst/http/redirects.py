from __future__ import annotations
from urllib.parse import urlparse

def summarize(probe: dict|None) -> dict:
    probe=probe or {}; hops=probe.get("redirects",[]) or []
    hosts=[]
    for hop in hops:
        url=str(hop.get("location") or hop.get("url") or "")
        if url:
            try: hosts.append(urlparse(url).hostname or "")
            except Exception: pass
    distinct=[x for i,x in enumerate(hosts) if x and x not in hosts[:i]]
    return {"hop_count":len(hops),"distinct_hosts":distinct,"cross_domain":len(distinct)>1,
            "cross_protocol_downgrade":any(str(h.get("location") or "").lower().startswith("http://") for h in hops),
            "loop_candidate":len(hosts)!=len(set(hosts)) and len(hosts)>2,"hops":hops}
