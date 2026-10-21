from __future__ import annotations
from collections import Counter
from typing import Any

BANNER_KEYS=('banner','service','product','software','server','version','title','port')

def _add(rows, *, source, value, kind='service', host=None, port=None, confidence=60, evidence=None):
    value=str(value).strip()
    if not value: return
    rows.append({'source':source,'value':value[:180],'kind':kind,'host':host,'port':port,'confidence':confidence,'evidence':evidence or source})

def build(result: dict[str, Any]) -> dict[str, Any]:
    rows=[]
    http=result.get('http') or {}
    headers={str(k).lower():v for k,v in (http.get('headers') or {}).items()}
    host=result.get('domain')
    if headers.get('server'): _add(rows,source='HTTP Server',value=headers['server'],kind='web-server',host=host,port=443,confidence=92,evidence='Server header')
    if headers.get('x-powered-by'): _add(rows,source='HTTP X-Powered-By',value=headers['x-powered-by'],kind='framework',host=host,port=443,confidence=88,evidence='X-Powered-By header')
    tls=result.get('tls') or {}
    if tls.get('tls_version'): _add(rows,source='TLS',value=tls['tls_version'],kind='tls-version',host=host,port=443,confidence=95,evidence='TLS handshake')
    if tls.get('cipher'): _add(rows,source='TLS',value=tls['cipher'][0] if isinstance(tls['cipher'],list) else tls['cipher'],kind='cipher',host=host,port=443,confidence=95,evidence='TLS handshake')
    for tech in result.get('technology') or []:
        if isinstance(tech,dict):
            _add(rows,source='Local technology fingerprint',value=tech.get('technology') or tech.get('name'),kind='technology',host=host,port=443,confidence=tech.get('confidence',70),evidence=tech.get('evidence'))
        else: _add(rows,source='Local technology fingerprint',value=tech,kind='technology',host=host,port=443,confidence=65)
    # DNSDumpster is intentionally parsed as provider data, never promoted to fact without provenance.
    dd=(result.get('dnsdumpster') or {}).get('records') or {}
    def walk(obj, ctx=None):
        if isinstance(obj,dict):
            for k,v in obj.items():
                lk=str(k).lower()
                if lk in BANNER_KEYS and isinstance(v,(str,int,float)) and str(v).strip():
                    _add(rows,source='DNSDumpster',value=v,kind=lk,host=ctx or host,confidence=78,evidence='DNSDumpster provider payload')
                elif lk in {'records','banners','services','a','aaaa','hosts','host'}:
                    walk(v,ctx)
                else:
                    walk(v,ctx)
        elif isinstance(obj,list):
            for v in obj: walk(v,ctx)
    walk(dd)
    seen=set(); dedup=[]
    for r in rows:
        key=(r['source'],r['value'],r.get('host'),r.get('port'))
        if key not in seen: seen.add(key); dedup.append(r)
    counts=Counter(r['kind'] for r in dedup)
    return {'status':'complete' if dedup else 'provider-dependent','count':len(dedup),'rows':dedup[:500],'kind_counts':dict(counts),'host_count':len({r.get('host') for r in dedup if r.get('host')}),'source_note':'Service/banner observations retain the provider and evidence used to produce each row.'}
