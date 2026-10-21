from __future__ import annotations
from typing import Any


def families(candidates:list[dict[str,Any]]) -> dict[str,list[dict[str,Any]]]:
    out={'omission':[],'insertion':[],'substitution':[],'transposition':[],'combo':[],'other':[]}
    for row in candidates or []:
        method=str(row.get('method','other')).lower() if isinstance(row,dict) else 'other'
        key='other'
        for fam in ('omission','insertion','substitution','transposition','combo'):
            if fam in method: key=fam; break
        out[key].append(row)
    return out
