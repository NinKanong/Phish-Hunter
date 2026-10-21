from __future__ import annotations
from typing import Any
import httpx

async def domain(client:httpx.AsyncClient, fqdn:str, token:str='')->dict[str,Any]:
    if not token:return {'status':'not_configured','provider':'SecurityTrails'}
    url=f'https://api.securitytrails.com/v1/domain/{fqdn}'
    try:
        r=await client.get(url,headers={'APIKEY':token,'accept':'application/json'})
        if r.status_code>=400:return {'status':r.status_code,'provider':'SecurityTrails','error':r.text[:300]}
        data=r.json(); return {'status':'completed','provider':'SecurityTrails','data':data}
    except Exception as exc:return {'status':'error','provider':'SecurityTrails','error':str(exc)[:300]}
