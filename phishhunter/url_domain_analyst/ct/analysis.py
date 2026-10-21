from __future__ import annotations
from collections import Counter

def analyze(ct: dict|None, domain: str) -> dict:
    ct=ct or {}; certs=ct.get('certificates',[]) or []; names=sorted(set(ct.get('names',[]) or []))
    issuers=Counter(str(c.get('issuer') or c.get('issuer_name') or 'unknown') for c in certs)
    return {'status':ct.get('status'),'certificate_count':len(certs),'discovered_names':names,'issuer_distribution':dict(issuers),
            'wildcard_count':sum(1 for c in certs if any(str(n).startswith('*.') for n in c.get('san',[]) or [])),
            'reused_fingerprint_count':len([fp for fp,c in Counter(str(c.get('sha256_fingerprint') or c.get('fingerprint','')) for c in certs).items() if c>1]),
            'notes':['CT discovery is historical/passive evidence; issuance does not establish current service availability.'],
            'raw_certificates':certs}
