def analyze(events): return {'tls_events':[x for x in events if x.get('event_type') in {'ssl','tls'}][:5000]}
