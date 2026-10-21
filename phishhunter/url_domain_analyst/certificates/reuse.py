from __future__ import annotations
from collections import defaultdict

def analyze(result:dict)->dict:
    certs=(result.get('certificate_transparency') or {}).get('certificates') or []
    by_issuer=defaultdict(list); by_fp=defaultdict(list); by_san=defaultdict(list)
    for c in certs[:5000]:
        issuer=str(c.get('issuer_name') or 'unknown'); by_issuer[issuer].append(c)
        fp=str(c.get('sha256_fingerprint') or c.get('fingerprint') or c.get('serial_number') or '')
        if fp: by_fp[fp].append(c)
        for san in c.get('san') or []: by_san[str(san).lower()].append(c)
    return {'issuer_distribution':sorted(((k,len(v)) for k,v in by_issuer.items()),key=lambda x:x[1],reverse=True)[:50], 'reused_fingerprints':[{'fingerprint':k,'count':len(v)} for k,v in by_fp.items() if len(v)>1][:100], 'multi_cert_names':[{'name':k,'cert_count':len(v)} for k,v in by_san.items() if len(v)>1][:100]}
