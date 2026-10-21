from __future__ import annotations
from collections import defaultdict

def infrastructure_clusters(graph:dict)->list[dict]:
    adj=defaultdict(set)
    for e in graph.get('edges',[]):
        adj[e['source']].add(e['target']); adj[e['target']].add(e['source'])
    clusters=[]; seen=set()
    for node in graph.get('nodes',[]):
        nid=node['id']
        if nid in seen: continue
        stack=[nid]; seen.add(nid); group=[]
        while stack:
            cur=stack.pop(); group.append(cur)
            for nxt in adj[cur]:
                if nxt not in seen: seen.add(nxt); stack.append(nxt)
        clusters.append({'cluster_id':f'C{len(clusters)+1:03d}','size':len(group),'members':group})
    return sorted(clusters,key=lambda x:x['size'],reverse=True)
