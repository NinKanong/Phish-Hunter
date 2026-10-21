from __future__ import annotations
import re
from typing import Any

API_RE=re.compile(r'https?://[^\"\'\\s)]+|(?:/api|/graphql|/rest|/oauth|/login)[A-Za-z0-9_./?=&%-]*',re.I)
SECRET_RE=re.compile(r'(?i)(api[_-]?key|secret|token|client[_-]?secret|access[_-]?token)\\s*[:=]\\s*[\"\']([^\"\']{8,})')

def analyze(scripts:list[str]) -> dict[str,Any]:
    endpoints=set(); indicators=[]
    for src in scripts or []:
        if not isinstance(src,str): continue
        for x in API_RE.findall(src)[:500]: endpoints.add(x[:500])
        for m in SECRET_RE.findall(src)[:100]: indicators.append({'type':'secret-like-literal','name':m[0],'value_hash':__import__('hashlib').sha256(m[1].encode()).hexdigest()})
    return {'api_endpoints':sorted(endpoints)[:1000],'secret_indicators':indicators[:500],'dynamic_execution':bool(re.search(r'(?i)\\b(eval|new Function|WebAssembly)\\b', ' '.join(scripts or []))),'source_map_hints':[x for x in scripts or [] if isinstance(x,str) and x.endswith('.map')][:200]}
