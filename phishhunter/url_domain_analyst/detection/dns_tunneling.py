from __future__ import annotations
from typing import Any

def score(labels:list[str], txt_records:list[str]) -> dict[str,Any]:
    rows=[]; total=0
    for label in labels or []:
        s=str(label or ''); total+=1
        if len(s)>=40: rows.append({'label':s,'signal':'long-label','score':35})
        if len(set(s.lower()))/max(1,len(s))>.72 and len(s)>=20: rows.append({'label':s,'signal':'high-character-diversity','score':25})
    for txt in txt_records or []:
        if len(str(txt))>=200: rows.append({'record':'TXT','signal':'large-txt','score':20})
    return {'score':min(100,sum(x['score'] for x in rows)),'signals':rows[:200],'assessment':'heuristic-only'}
