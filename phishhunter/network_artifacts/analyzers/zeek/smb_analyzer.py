def analyze(events): return {'smb_events':[x for x in events if x.get('event_type')=='smb'][:5000]}
