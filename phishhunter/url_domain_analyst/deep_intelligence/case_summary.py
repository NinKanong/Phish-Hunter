from __future__ import annotations

def build(result:dict)->dict:
    v=result.get('url_domain_vnext') if isinstance(result.get('url_domain_vnext'),dict) else {}
    surface=v.get('attack_surface') if isinstance(v.get('attack_surface'),dict) else {}
    summary=surface.get('summary') if isinstance(surface.get('summary'),dict) else {}
    return {'target':result.get('target'),'domain':result.get('domain'),'risk_score':result.get('risk_score',0),'verdict':result.get('verdict'),'coverage':summary,'provider_error_count':len(v.get('provider_error_ledger') or []),'source_first':True}
