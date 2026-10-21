from __future__ import annotations
from typing import Any

SIGNATURES={
 'Cloudflare':('cf-ray','__cf_bm','cloudflare'), 'Akamai':('akamai','akamai'), 'Fastly':('fastly','fastly'),
 'Imperva':('incap_ses','visid_incap','imperva'), 'AWS CloudFront':('x-amz-cf-id','cloudfront'),
 'AWS WAF':('x-amzn-waf','awselb'), 'Sucuri':('sucuri','sucuri'), 'F5':('bigipserver','f5')
}

def detect(headers:dict[str,Any]) -> dict[str,Any]:
    h={str(k).lower():str(v).lower() for k,v in (headers or {}).items()}
    cdn=[]; waf=[]
    joined=' '.join(list(h.keys())+list(h.values()))
    for name,needles in SIGNATURES.items():
        if any(n in joined for n in needles):
            row={'name':name,'confidence':82,'evidence':needles}
            if name in {'AWS WAF','Imperva','Sucuri','F5','Cloudflare'}: waf.append(row)
            if name in {'Cloudflare','Akamai','Fastly','AWS CloudFront','Sucuri','Imperva','F5'}: cdn.append(row)
    return {'cdn':cdn,'waf':waf,'note':'Signature-based public HTTP inference; not proof of internal architecture.'}
