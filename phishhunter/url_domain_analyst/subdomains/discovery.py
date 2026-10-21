from __future__ import annotations

def certificate_names(ct:dict|None)->list[str]: return sorted(set((ct or {}).get('names') or []))

def passive_candidates(domain:str, ct:dict|None=None)->list[dict]:
    return [{'hostname':x,'source':'certificate-transparency','verification':'required'} for x in certificate_names(ct) if x.endswith(domain)]
