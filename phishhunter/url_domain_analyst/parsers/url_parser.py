from __future__ import annotations
from urllib.parse import urlparse

def parse_target(value: str) -> dict:
    raw=value.strip()
    candidate=raw if "://" in raw else "https://"+raw
    p=urlparse(candidate)
    return {"raw":raw,"candidate":candidate,"scheme":p.scheme.lower(),"hostname":p.hostname,"port":p.port,"path":p.path,"query":p.query,"fragment":p.fragment,"username":p.username,"has_password":bool(p.password)}
