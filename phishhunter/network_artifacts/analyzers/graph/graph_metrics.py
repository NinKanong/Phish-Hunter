from __future__ import annotations

def metrics(graph):
    nodes=graph.get('nodes',[]); edges=graph.get('edges',[])
    degree={n.get('id'):0 for n in nodes}
    for e in edges:
        degree[e.get('source')]=degree.get(e.get('source'),0)+int(e.get('weight') or 1)
        degree[e.get('target')]=degree.get(e.get('target'),0)+int(e.get('weight') or 1)
    ranked=sorted(({'id':k,'degree':v} for k,v in degree.items()),key=lambda x:-x['degree'])
    return {'node_count':len(nodes),'edge_count':len(edges),'top_central_nodes':ranked[:25],'method':'degree centrality; NetworkX optional for richer deployments'}
