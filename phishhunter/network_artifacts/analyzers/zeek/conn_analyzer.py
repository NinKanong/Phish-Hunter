from collections import Counter
def analyze(events): return {'connections':len(events),'protocols':dict(Counter(str(x.get('protocol') or 'unknown') for x in events))}
