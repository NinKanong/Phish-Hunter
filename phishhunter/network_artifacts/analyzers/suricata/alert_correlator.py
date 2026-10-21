def correlate(events): return [x for x in events if x.get('event_type')=='alert'][:5000]
