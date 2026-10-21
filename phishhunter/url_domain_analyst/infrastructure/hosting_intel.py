from __future__ import annotations
from typing import Any

CLOUD_HINTS={
 'amazonaws.com':'AWS','cloudfront.net':'AWS CloudFront','azurewebsites.net':'Azure App Service','windows.net':'Microsoft Azure',
 'googleusercontent.com':'Google Cloud','appspot.com':'Google App Engine','cloudflare':'Cloudflare','fastly':'Fastly','akamai':'Akamai',
 'digitalocean':'DigitalOcean','linode':'Akamai/Linode','vultr':'Vultr'
}


def infer_from_names(hostnames:list[str]) -> list[dict[str,Any]]:
    rows=[]; seen=set()
    for host in hostnames or []:
        low=str(host or '').lower()
        for needle,provider in CLOUD_HINTS.items():
            if needle in low and provider not in seen:
                seen.add(provider); rows.append({'provider':provider,'evidence_host':host,'confidence':72,'basis':'hostname relationship'})
    return rows


def summarize(ips:list[dict[str,Any]], asn:dict[str,Any]|None=None) -> dict[str,Any]:
    orgs=[]; netblocks=[]
    for row in ips or []:
        if not isinstance(row,dict): continue
        if row.get('asn_org'): orgs.append(str(row['asn_org']))
        if row.get('netblock'): netblocks.append(str(row['netblock']))
    return {'organizations':sorted(set(orgs)),'netblocks':sorted(set(netblocks)),'asn':asn or {}}
