from __future__ import annotations
from typing import Any
import httpx

async def ipinfo(client:httpx.AsyncClient, ip:str, token:str='')->dict[str,Any]:
    if not token: return {'status':'not_configured','provider':'IPinfo','ip':ip}
    try:
        r=await client.get(f'https://ipinfo.io/{ip}/json',headers={'Authorization':f'Bearer {token}'},timeout=20)
        if r.status_code>=400:return {'status':r.status_code,'provider':'IPinfo','ip':ip,'error':r.text[:300]}
        d=r.json(); loc=str(d.get('loc') or '').split(',')
        lat=float(loc[0]) if len(loc)==2 else None; lon=float(loc[1]) if len(loc)==2 else None
        return {'status':'completed','provider':'IPinfo','ip':ip,'country':d.get('country'),'region':d.get('region'),'city':d.get('city'),'lat':lat,'lon':lon,'org':d.get('org'),'hostname':d.get('hostname'),'timezone':d.get('timezone'),'postal':d.get('postal')}
    except Exception as exc:return {'status':'error','provider':'IPinfo','ip':ip,'error':str(exc)[:300]}
