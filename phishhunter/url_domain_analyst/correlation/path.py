from __future__ import annotations
from collections import deque, defaultdict

def shortest_path(graph:dict, start:str, goal:str) -> list[str]:
    adj=defaultdict(list)
    for e in graph.get("edges",[]) or []:
        adj[e["source"]].append(e["target"]); adj[e["target"]].append(e["source"])
    q=deque([start]); parent={start:None}
    while q:
        cur=q.popleft()
        if cur==goal: break
        for nxt in adj[cur]:
            if nxt not in parent: parent[nxt]=cur; q.append(nxt)
    if goal not in parent: return []
    path=[]; cur=goal
    while cur is not None: path.append(cur); cur=parent[cur]
    return list(reversed(path))
