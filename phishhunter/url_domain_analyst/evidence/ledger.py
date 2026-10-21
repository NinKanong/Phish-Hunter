from __future__ import annotations
from datetime import datetime, timezone
import hashlib, json

def build(result:dict)->dict:
    records=[]
    for source,key in [('url','url_forensics'),('rdap','whois_rdap'),('dns','dns'),('ct','certificate_transparency'),('http','http'),('tls','tls'),('reputation','reputation'),('breach','breach_intelligence')]:
        value=result.get(key)
        raw=json.dumps(value,sort_keys=True,default=str,separators=(',',':'))
        records.append({'evidence_id':f'EV-{source.upper()}-{hashlib.sha1(raw.encode()).hexdigest()[:12]}','source':source,
                        'observed_at':datetime.now(timezone.utc).isoformat(),'sha256':hashlib.sha256(raw.encode()).hexdigest(),'value':value})
    package={'target':result.get('target'),'records':records}; digest=hashlib.sha256(json.dumps(package,sort_keys=True,default=str).encode()).hexdigest()
    return {'records':records,'count':len(records),'package_sha256':digest,'chain_of_custody':'deterministic digest over retained evidence records'}
