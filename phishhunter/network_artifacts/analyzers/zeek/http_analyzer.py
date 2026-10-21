def analyze(events): return {'http_events':[x for x in events if x.get('event_type')=='http'][:5000]}
