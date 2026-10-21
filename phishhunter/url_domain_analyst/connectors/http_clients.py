from __future__ import annotations
import os
from typing import Any
import httpx

class SafeProviderClient:
    def __init__(self, base_url:str, api_key_env:str|None=None, timeout:float=15.0):
        self.base_url=base_url.rstrip('/'); self.api_key_env=api_key_env; self.timeout=timeout
    def headers(self)->dict[str,str]:
        key=os.getenv(self.api_key_env or '') if self.api_key_env else None
        return {'User-Agent':'Phish-Hunter/URL-Domain-Analyst','Accept':'application/json',**({'X-API-Key':key} if key else {})}
    async def get(self,path:str,params:dict[str,Any]|None=None)->dict:
        url=f'{self.base_url}/{path.lstrip("/")}'
        async with httpx.AsyncClient(timeout=self.timeout,follow_redirects=False) as c:
            r=await c.get(url,params=params or {},headers=self.headers())
            data=None
            try:data=r.json()
            except Exception:data={'text':r.text[:10000]}
            return {'status_code':r.status_code,'url':str(r.url),'data':data}
