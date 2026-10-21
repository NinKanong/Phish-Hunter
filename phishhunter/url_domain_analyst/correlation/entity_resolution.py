from __future__ import annotations
from collections import defaultdict
import re

def normalize_entity(value:str)->str: return re.sub(r'\.+$','',value.strip().lower())

def resolve(rows:list[dict])->dict:
    groups=defaultdict(list)
    for row in rows:
        key=normalize_entity(str(row.get('value') or row.get('label') or ''))
        if key: groups[key].append(row)
    return {'groups':[{'canonical':k,'members':v,'count':len(v)} for k,v in groups.items()],'unique_entities':len(groups)}
