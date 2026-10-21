from __future__ import annotations
from ..connectors.capability_registry import CAPABILITY_CATEGORIES

def run_family(category:str, target:str, context:dict|None=None)->dict:
    match=[x for x in CAPABILITY_CATEGORIES if x[0]==category]
    if not match: return {"status":"unknown-family","category":category,"target":target}
    count=match[0][1]
    return {"status":"contract-ready","category":category,"target":target,"capability_count":count,
            "execution":"provider/module dependent","context_keys":sorted((context or {}).keys())}

def run_selection(categories:list[str], target:str)->list[dict]:
    return [run_family(c,target) for c in categories]
