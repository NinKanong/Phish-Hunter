from __future__ import annotations
from collections import defaultdict, deque
from typing import Any


def neighborhood(graph:dict[str,Any], node_id:str, depth:int=1) -> dict[str,Any]:
    nodes={x.get('id'):x for x in (graph.get('nodes') or []) if isinstance(x,dict) and x.get('id')}
    edges=[x for x in (graph.get('edges') or []) if isinstance(x,dict)]
    seen={node_id}; q=deque([(node_id,0)])
    while q:
        cur,d=q.popleft()
        if d>=max(0,min(depth,5)): continue
        for e in edges:
            if e.get('source')==cur: nxt=e.get('target')
            elif e.get('target')==cur: nxt=e.get('source')
            else: continue
            if nxt and nxt not in seen: seen.add(nxt); q.append((nxt,d+1))
    return {'root':node_id,'depth':depth,'nodes':[nodes[x] for x in seen if x in nodes],'edges':[e for e in edges if e.get('source') in seen and e.get('target') in seen]}


def degree_centrality(graph:dict[str,Any]) -> list[dict[str,Any]]:
    deg=defaultdict(int)
    for e in graph.get('edges') or []:
        if isinstance(e,dict): deg[e.get('source')]+=1; deg[e.get('target')]+=1
    return sorted([{'id':k,'degree':v} for k,v in deg.items() if k],key=lambda x:x['degree'],reverse=True)
