from __future__ import annotations
from collections import Counter
import math,re

def _entropy(s):
    c=Counter(s);n=len(s) or 1
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def detect(domains):
    out=[]
    for d in sorted(set(str(x).lower().rstrip('.') for x in domains if x)):
        label=d.split('.')[0] if '.' in d else d
        digits=sum(c.isdigit() for c in label)/max(1,len(label))
        if len(label)>=10 and _entropy(label)>=3.5 and digits>=0.1:
            out.append({'domain':d,'entropy':round(_entropy(label),3),'digit_ratio':round(digits,3),'confidence':50,'reason':'heuristic DGA-like lexical characteristics'})
    return out[:1000]
