from __future__ import annotations
from datetime import datetime, timezone

def lifecycle(rdap: dict|None) -> dict:
    rdap=rdap or {}; events=rdap.get('events',[]) or []
    creation=next((x.get('date') for x in events if x.get('event_action') in {'registration','registered'}),None)
    updated=next((x.get('date') for x in events if x.get('event_action') in {'last changed','last update','last changed date'}),None)
    expiry=next((x.get('date') for x in events if x.get('event_action') in {'expiration','expiry'}),None)
    age=None
    if creation:
        try: age=(datetime.now(timezone.utc)-datetime.fromisoformat(creation.replace('Z','+00:00'))).days
        except Exception: pass
    registrar_entities=[e for e in rdap.get('entities',[]) if 'registrar' in [str(x).lower() for x in e.get('roles',[])]]
    registrar=registrar_entities[0] if registrar_entities else {}
    return {'status_codes':rdap.get('status_codes',[]),'creation_date':creation,'updated_date':updated,'expiration_date':expiry,
            'domain_age_days':age,'registrar':registrar,'nameservers':rdap.get('name_servers',[]),'secure_dns':rdap.get('secure_dns',{}),
            'privacy_indicators':{'redacted_fields':sum(1 for e in rdap.get('entities',[]) for k,v in e.items() if k in {'name','email','phone'} and not v)}}
