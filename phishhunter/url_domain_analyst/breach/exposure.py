from __future__ import annotations

def analyze(records:dict|None)->dict:
    r=records or {}; status=str(r.get('status') or 'not_configured'); rows=r.get('records') or r.get('breaches') or []
    return {'status':status,'record_count':len(rows),'records':rows,'domain_search_authorization_required':True,
            'direct_dark_web_crawl':False,'provider_boundary':'Only authorized provider APIs / verified domain searches are treated as breach evidence.',
            'confidence':'provider-scoped'}
