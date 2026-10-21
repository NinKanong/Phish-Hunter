from __future__ import annotations
import math
from collections import Counter

def levenshtein(a: str,b: str)->int:
    a,b=a or '',b or ''
    if len(a)>len(b): a,b=b,a
    prev=list(range(len(a)+1))
    for i,cb in enumerate(b,1):
        cur=[i]
        for j,ca in enumerate(a,1):
            cur.append(min(cur[-1]+1,prev[j]+1,prev[j-1]+(ca!=cb)))
        prev=cur
    return prev[-1]

def jaccard_tokens(a: str,b: str)->float:
    sa=set((a or '').lower().replace('/',' ').replace('.',' ').split())
    sb=set((b or '').lower().replace('/',' ').replace('.',' ').split())
    return len(sa&sb)/len(sa|sb) if sa|sb else 1.0

def similarity(a: str,b: str)->dict:
    dist=levenshtein(a,b)
    mx=max(len(a or ''),len(b or ''),1)
    return {'levenshtein':dist,'normalized':round(1-dist/mx,4),'jaccard_tokens':round(jaccard_tokens(a,b),4),'length_delta':abs(len(a or '')-len(b or ''))}
