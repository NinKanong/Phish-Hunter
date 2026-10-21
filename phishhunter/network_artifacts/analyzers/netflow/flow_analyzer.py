from collections import Counter
def analyze(events): return {'flow_count':len(events),'top_ports':dict(Counter(e.get('dst_port') for e in events if e.get('dst_port')).most_common(100))}
