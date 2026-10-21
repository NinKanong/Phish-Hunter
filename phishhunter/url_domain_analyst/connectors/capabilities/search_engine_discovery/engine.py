from __future__ import annotations
from .manifest import NAME, COUNT

def capability_ids()->list[str]:
    return [f"{NAME}.{i:03d}" for i in range(1, COUNT+1)]

def analyze(target:str, context:dict|None=None)->dict:
    return {'capability_family':NAME,'target':target,'capabilities':capability_ids(),'status':'contract-ready','context_keys':sorted((context or {}).keys())}
