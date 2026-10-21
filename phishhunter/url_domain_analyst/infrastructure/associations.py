from __future__ import annotations
from collections import Counter
import ipaddress, re

CDN_MARKERS={'cloudflare':['cloudflare','cf-ray'],'fastly':['fastly','x-served-by'],'akamai':['akamai','x-akamai'],'cloudfront':['cloudfront','x-amz-cf'],'azure':['azure','x-azure-ref']}
WAF_MARKERS={'cloudflare':['cf-ray','cf-cache-status'],'imperva':['imperva','incap_ses'],'sucuri':['sucuri','x-sucuri-id'],'aws-waf':['x-amzn-waf-action']}

def analyze(ip_rows:list[dict]|None, http:dict|None, dns:dict|None) -> dict:
    ip_rows=ip_rows or []; http=http or {}; headers={str(k).lower():str(v).lower() for k,v in (http.get('headers') or {}).items()}
    cdns=[name for name,markers in CDN_MARKERS.items() if any(m in ' '.join([*headers.keys(),*headers.values()]) for m in markers)]
    wafs=[name for name,markers in WAF_MARKERS.items() if any(m in ' '.join([*headers.keys(),*headers.values()]) for m in markers)]
    asns=Counter(str(r.get('asn') or 'unknown') for r in ip_rows)
    return {'ips':ip_rows,'asn_distribution':dict(asns),'cdn_candidates':cdns,'waf_candidates':wafs,
            'hosting':{'provider_candidates':sorted(set([str(r.get('organization')) for r in ip_rows if r.get('organization')])),'confidence':'heuristic'},
            'network_location':{'countries':sorted(set([str(r.get('country')) for r in ip_rows if r.get('country')])),'regions':sorted(set([str(r.get('region')) for r in ip_rows if r.get('region')]))},
            'neighboring_netblocks':'provider-dependent','bgp':'provider-dependent'}
