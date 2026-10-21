from __future__ import annotations
import csv,io,json
from hashlib import sha256
from typing import Any

def json_report(result): return json.dumps(result,indent=2,default=str).encode()
def csv_iocs(result):
    out=io.StringIO();w=csv.writer(out);w.writerow(['type','value'])
    for k,vals in (result.get('iocs') or {}).items():
        for v in vals or []:w.writerow([k,v])
    return out.getvalue().encode()
def csv_events(result):
    out=io.StringIO();w=csv.writer(out);cols=['event_id','timestamp','source','event_type','src_ip','src_port','dst_ip','dst_port','protocol','hostname','action','severity','bytes','packets','message'];w.writerow(cols)
    for i,e in enumerate(result.get('events') or [],1):w.writerow([e.get('event_id') or f'EV-{i:06d}']+[e.get(k) for k in cols[1:]])
    return out.getvalue().encode()
def _stix_id(t,v):
    d=sha256(f'{t}:{v}'.encode()).hexdigest();return f'{t}--{d[:8]}-{d[8:12]}-5{d[13:16]}-{d[16:20]}-{d[20:32]}'
def stix_bundle(result):
    objects=[]
    for kind,values in (result.get('iocs') or {}).items():
        for value in values or []:
            value=str(value)
            if kind in {'ips','ipv4'}: objects.append({'type':'ipv4-addr','spec_version':'2.1','id':_stix_id('ipv4-addr',value),'value':value})
            elif kind=='ipv6':objects.append({'type':'ipv6-addr','spec_version':'2.1','id':_stix_id('ipv6-addr',value),'value':value})
            elif kind=='domains':objects.append({'type':'domain-name','spec_version':'2.1','id':_stix_id('domain-name',value),'value':value})
            elif kind=='urls':objects.append({'type':'url','spec_version':'2.1','id':_stix_id('url',value),'value':value})
            elif kind=='hashes':
                htype='SHA-256' if len(value)==64 else 'SHA-1' if len(value)==40 else 'MD5' if len(value)==32 else None
                if htype:objects.append({'type':'file','spec_version':'2.1','id':_stix_id('file',value),'hashes':{htype:value}})
            elif kind=='emails':objects.append({'type':'email-addr','spec_version':'2.1','id':_stix_id('email-addr',value),'value':value})
    digest=sha256(b'k4-network-artifacts-stix-2.1').hexdigest()
    return json.dumps({'type':'bundle','id':f'bundle--{digest[:8]}-{digest[8:12]}-5{digest[13:16]}-{digest[16:20]}-{digest[20:32]}','objects':objects},indent=2).encode()
