from __future__ import annotations
from typing import Any
from urllib.parse import urlparse


def assess(parsed: dict[str, Any]) -> dict[str, Any]:
    signals=[]
    q=parsed.get('query') if isinstance(parsed.get('query'),dict) else {}
    path=parsed.get('path') if isinstance(parsed.get('path'),dict) else {}
    host=parsed.get('host') if isinstance(parsed.get('host'),dict) else {}
    if parsed.get('authority',{}).get('userinfo_present'): signals.append(('userinfo',18,'Credentials/userinfo embedded in authority'))
    if path.get('traversal'): signals.append(('path-traversal-marker',15,'Traversal sequence observed after parsing'))
    if q.get('secret_parameter_count',0): signals.append(('secret-parameter',12,'Potential secret-like query parameter observed'))
    if parsed.get('fragment',{}).get('potential_token'): signals.append(('fragment-token',10,'Fragment contains a token-like marker'))
    if host.get('mixed_scripts'): signals.append(('mixed-script-host',25,'Hostname mixes writing systems'))
    if host.get('idn'): signals.append(('idn-host',10,'Internationalized/Punycode hostname'))
    if not parsed.get('scheme_secure'): signals.append(('insecure-scheme',8,'URL does not use a secure transport scheme'))
    return {'score':min(100,sum(x[1] for x in signals)),'signals':[{'name':n,'weight':w,'reason':r} for n,w,r in signals]}
