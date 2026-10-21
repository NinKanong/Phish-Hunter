from __future__ import annotations
from typing import Any


def diff(before:dict[str,Any], after:dict[str,Any], keys:tuple[str,...]=('dns','technology','certificate_transparency','http')) -> dict[str,Any]:
    changes=[]
    for key in keys:
        a=before.get(key); b=after.get(key)
        if a != b:
            changes.append({'key':key,'changed':True,'before_hash':__import__('hashlib').sha256(repr(a).encode()).hexdigest(),'after_hash':__import__('hashlib').sha256(repr(b).encode()).hexdigest()})
    return {'changed':bool(changes),'change_count':len(changes),'changes':changes}
