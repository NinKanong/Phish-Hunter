from __future__ import annotations

def summarize(history:dict|None)->dict:
    h=history or {}
    return {'status':h.get('status','provider-required'),'a_history':h.get('a_history',[]),'ns_history':h.get('ns_history',[]),'mx_history':h.get('mx_history',[]),
            'first_seen':h.get('first_seen'),'last_seen':h.get('last_seen'),'fast_flux':'requires time-series observations'}
