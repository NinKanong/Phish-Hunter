from __future__ import annotations

def build(result:dict)->list[dict]:
    domain=result.get('domain',''); url=result.get('url',''); ips=(result.get('network_associations') or {}).get('current_ips') or []
    piv=[]
    def add(kind,target,why,source='derived'):
        if target: piv.append({'kind':kind,'target':str(target),'why':why,'source':source})
    add('Search','site:'+domain,'Discover indexed pages')
    add('Search','"'+domain+'"','Find exact-domain mentions')
    add('Certificate','crt.sh/?q=%25.'+domain,'Review CT hostnames')
    for ip in ips[:20]: add('IP','reverse:'+ip,'Pivot from current address')
    add('Archive','web.archive.org/*/'+domain+'/*','Review historical snapshots')
    add('Technology','technology:'+domain,'Compare stack fingerprints')
    add('Breach','breach:'+domain,'Use authorized provider coverage')
    if url: add('URL','unfurl:'+url,'Decompose URL/redirect indicators')
    return piv[:200]
