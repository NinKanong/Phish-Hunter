from __future__ import annotations
from collections import Counter,defaultdict
import ipaddress

def _scope(v):
    try:
        ip=ipaddress.ip_address(v); return 'private' if ip.is_private else 'public' if ip.is_global else 'special'
    except Exception:return 'unknown'

def build(events):
    nodes={}; edges=Counter(); labels=defaultdict(set)
    for e in events:
        s,d=e.get('src_ip'),e.get('dst_ip'); h=e.get('hostname')
        if s:nodes.setdefault(s,{'id':s,'type':'host','scope':_scope(s)})
        if d:nodes.setdefault(d,{'id':d,'type':'host','scope':_scope(d)})
        if h:
            labels[d].add(h)
            nodes.setdefault(h,{'id':h,'type':'domain','scope':'external'})
            if d:edges[(d,h,'resolves/observed')]+=1
        if s and d:edges[(s,d,str(e.get('protocol') or 'unknown'))]+=1
    for nid,n in nodes.items():
        if labels.get(nid): n['labels']=sorted(labels[nid])[:20]
    return {'nodes':list(nodes.values()),'edges':[{'source':s,'target':d,'protocol':p,'weight':w} for (s,d,p),w in edges.items()]}
