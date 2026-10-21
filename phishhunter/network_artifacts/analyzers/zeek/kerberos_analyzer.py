def analyze(events): return {'kerberos_events':[x for x in events if x.get('event_type')=='kerberos'][:5000]}
