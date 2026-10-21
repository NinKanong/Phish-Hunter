from __future__ import annotations
from collections import Counter, defaultdict

def metrics(graph: dict) -> dict:
    degree=Counter()
    adj=defaultdict(set)
    for e in graph.get("edges",[]) or []:
        degree[e["source"]]+=1; degree[e["target"]]+=1; adj[e["source"]].add(e["target"]); adj[e["target"]].add(e["source"])
    top=degree.most_common(20)
    return {"node_degree":dict(degree),"top_connected":top,"orphan_count":sum(1 for n in graph.get("nodes",[]) if not adj[n["id"]]),
            "graph_density":(len(graph.get("edges",[]))*2/max(1,len(graph.get("nodes",[]))*(len(graph.get("nodes",[]))-1)))}
