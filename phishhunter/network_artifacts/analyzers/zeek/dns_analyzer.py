def analyze(events): return {'dns_events':[x for x in events if x.get('event_type')=='dns'][:5000]}
