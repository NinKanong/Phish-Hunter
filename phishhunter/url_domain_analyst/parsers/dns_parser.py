from __future__ import annotations

def record_inventory(bundle: dict|None) -> list[dict]:
    rows=[]
    for rtype, values in ((bundle or {}).get("records",{}) or {}).items():
        for row in values or []:
            rows.append({"type":rtype,"name":row.get("name"),"value":row.get("value") or row.get("data"),"ttl":row.get("ttl")})
    return rows
