from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

UTC=timezone.utc


def lifecycle(rdap: dict[str,Any]) -> dict[str,Any]:
    data=rdap if isinstance(rdap,dict) else {}
    events=[x for x in data.get('events',[]) if isinstance(x,dict)]
    def first(*names):
        for row in events:
            if str(row.get('event_action','')).lower() in names and row.get('date'):
                return row.get('date')
        return None
    created=first('registration','registered','creation')
    updated=first('last changed','last changed date','update','updated')
    expires=first('expiration','expiry','expiration date')
    age=None
    if created:
        try: age=max(0,(datetime.now(UTC)-datetime.fromisoformat(str(created).replace('Z','+00:00'))).days)
        except Exception: pass
    entities=[x for x in data.get('entities',[]) if isinstance(x,dict)]
    registrar=next((x for x in entities if 'registrar' in [str(r).lower() for r in (x.get('roles') or [])]),None)
    return {'creation':created,'updated':updated,'expiration':expires,'age_days':age,'registrar':registrar,'entity_count':len(entities),'registration_jurisdiction':None}
