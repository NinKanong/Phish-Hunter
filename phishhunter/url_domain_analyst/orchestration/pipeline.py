from __future__ import annotations

STAGES=[
    'normalize','parse-url','parse-domain','dns','rdap','ct','pdns','subdomains','ip-asn','hosting-cdn-waf',
    'http','tls','content','security-detections','reputation','breach-exposure','correlation','risk','evidence','ai','reporting'
]

def plan() -> list[dict]:
    return [{"sequence":i+1,"stage":s,"status":"ready"} for i,s in enumerate(STAGES)]
