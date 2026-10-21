from __future__ import annotations
from urllib.parse import urlparse

SECURITY_HEADERS=['content-security-policy','strict-transport-security','x-content-type-options','x-frame-options','referrer-policy','permissions-policy','cross-origin-opener-policy','cross-origin-embedder-policy','cross-origin-resource-policy','clear-site-data','nel','report-to']

def analyze(probe:dict|None) -> dict:
    probe=probe or {}; headers={str(k).lower():str(v) for k,v in (probe.get('headers') or {}).items()}
    cookies=probe.get('cookies') or []
    forms=probe.get('forms') or []; links=probe.get('links') or []; scripts=probe.get('scripts') or []
    form_risks=[]
    for f in forms:
        action=str(f.get('action') or '')
        if action and probe.get('final_url') and urlparse(action).netloc and urlparse(action).netloc != urlparse(str(probe.get('final_url'))).netloc:
            form_risks.append({'type':'cross-origin-form-action','action':action})
    return {'status_code':probe.get('status_code'),'final_url':probe.get('final_url'),'redirect_count':probe.get('redirect_count',0),
      'response_headers':headers,'security_headers':{h:headers.get(h) for h in SECURITY_HEADERS},
      'missing_security_headers':[h for h in SECURITY_HEADERS if h not in headers],
      'cookies':cookies,'cookie_issues':[c for c in cookies if not str(c).lower().find('secure')>=0],
      'forms':forms,'cross_origin_form_actions':form_risks,'links_count':len(links),'scripts_count':len(scripts),
      'html_sample_length':len(str(probe.get('html_sample') or '')),
      'unsafe_content_execution':False,
      'analysis_boundary':'Static HTTP response parsing; page JavaScript is not executed by this module.'}
