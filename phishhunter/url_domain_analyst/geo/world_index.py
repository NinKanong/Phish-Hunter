from __future__ import annotations
import json
from pathlib import Path

_DATA=Path(__file__).with_name('country_centers.json')
try:
    COUNTRY_INDEX=json.loads(_DATA.read_text(encoding='utf-8'))
except Exception:
    COUNTRY_INDEX={}

def country(code: str|None) -> dict:
    return COUNTRY_INDEX.get(str(code or '').upper(), {})

def layers(observations):
    counts={}
    for row in observations or []:
        if not isinstance(row,dict): continue
        code=str(row.get('country_code') or '').upper()
        if not code:
            name=str(row.get('country') or '').strip().lower()
            for c,v in COUNTRY_INDEX.items():
                if str(v.get('name','')).lower()==name: code=c; break
        if not code: continue
        item=COUNTRY_INDEX.get(code)
        if not item: continue
        counts.setdefault(code, {'code':code,'name':item['name'],'lat':item['lat'],'lon':item['lon'],'count':0,'ips':[]})
        counts[code]['count'] += int(row.get('count') or 1)
        if row.get('ip'): counts[code]['ips'].append(str(row['ip']))
    return sorted(counts.values(), key=lambda x:(-x['count'],x['name']))
