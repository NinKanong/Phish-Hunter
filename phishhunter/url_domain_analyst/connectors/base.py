from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(slots=True)
class ConnectorSpec:
    name: str
    category: str
    auth_env: str|None = None
    endpoint: str|None = None
    mode: str = 'provider-dependent'
    notes: str = ''

class Connector:
    spec: ConnectorSpec
    async def query(self, target:str, **kwargs:Any)->dict:
        return {'status':'not_configured','provider':self.spec.name,'target':target,'mode':self.spec.mode}

def health(spec:ConnectorSpec, env:dict[str,str])->dict:
    configured=bool(spec.auth_env and env.get(spec.auth_env)) if spec.auth_env else False
    return {'name':spec.name,'category':spec.category,'status':'live-configured' if configured else 'catalog-only','auth_env':spec.auth_env,'endpoint':spec.endpoint,'mode':spec.mode}
