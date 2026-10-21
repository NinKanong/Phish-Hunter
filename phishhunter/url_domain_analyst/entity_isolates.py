from __future__ import annotations
from typing import Any
from .attack_surface_contract import from_row

def build_host_isolate(row: Any) -> dict[str,Any]:
    item=from_row(row)
    d=item.to_dict()
    d["pivot_targets"]=[
        {"kind":"ip","value":item.ip,"label":"Inspect IP / ASN relationships"} if item.ip else None,
        {"kind":"asn","value":item.asn,"label":"Inspect network ownership"} if item.asn else None,
        {"kind":"country","value":item.country,"label":"Inspect system location"} if item.country else None,
        {"kind":"ptr","value":item.ptr,"label":"Inspect reverse DNS"} if item.ptr else None,
    ]
    d["pivot_targets"]= [x for x in d["pivot_targets"] if x]
    return {"entity_type":"host","entity":d,"evidence_scope":"single returned attack-surface row"}
