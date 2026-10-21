from __future__ import annotations
from collections import Counter,defaultdict
import math

def entropy(s):
    if not s:return 0.0
    c=Counter(s); n=len(s)
    return -sum((x/n)*math.log2(x/n) for x in c.values())

def detect(queries):
    out=[]
    for q in queries:
        details=q.get('details') or q.get('dns') or {}
        for item in details.get('questions',[]):
            name=str(item.get('name') or '').rstrip('.').lower()
            labels=name.split('.')
            if not name:continue
            longest=max(map(len,labels),default=0); ent=max((entropy(x) for x in labels),default=0)
            if longest>=35 or ent>=4.2:
                out.append({'domain':name,'longest_label':longest,'entropy':round(ent,3),'confidence':55,'reason':'long or high-entropy DNS label'})
    return out[:1000]
