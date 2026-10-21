from __future__ import annotations
from typing import Any
from urllib.parse import quote
import httpx

IRIS='https://api.domaintools.com/v1/iris-investigate/'
PROFILE='https://api.domaintools.com/v1/{domain}/'
WHOIS='https://api.domaintools.com/v1/{domain}/whois/'

async def _get(client:httpx.AsyncClient, url:str, key:str, params:dict[str,Any]|None=None)->dict[str,Any]:
    if not key: return {'status':'not_configured','provider':'DomainTools'}
    try:
        r=await client.get(url,headers={'X-Api-Key':key,'accept':'application/json'},params=params or {},timeout=20)
        if r.status_code>=400:
            return {'status':r.status_code,'provider':'DomainTools','error':r.text[:500]}
        data=r.json()
        return {'status':'completed','provider':'DomainTools','data':data,'request_url':str(r.url)}
    except Exception as exc:
        return {'status':'error','provider':'DomainTools','error':str(exc)[:500]}

async def investigate(client:httpx.AsyncClient, domain:str, api_key:str)->dict[str,Any]:
    return await _get(client,IRIS,api_key,{'domain':domain})

async def profile(client:httpx.AsyncClient, domain:str, api_key:str)->dict[str,Any]:
    return await _get(client,PROFILE.format(domain=quote(domain,safe='')),api_key)

async def whois(client:httpx.AsyncClient, domain:str, api_key:str)->dict[str,Any]:
    return await _get(client,WHOIS.format(domain=quote(domain,safe='')),api_key)


def web_links(domain:str)->dict[str,str]:
    return {
      'whois':f'https://whois.domaintools.com/{quote(domain,safe="")}',
      'iris':f'https://iris.domaintools.com/investigate/?query={quote(domain,safe="")}',
      'docs':'https://docs.domaintools.com/api/iris/investigate/',
    }
