from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


def _event(events:list[dict[str,Any]], names:set[str]) -> str|None:
    for row in events:
        if not isinstance(row, dict):
            continue
        action=str(row.get('event_action') or '').strip().lower()
        if action in names and row.get('date'):
            return str(row['date'])
    return None


def _registrar_entity(entities:list[dict[str,Any]]) -> dict[str,Any]:
    for entity in entities:
        roles={str(x).lower() for x in (entity.get('roles') or [])}
        if 'registrar' in roles:
            return entity
    return {}


def build(domain:str, rdap:dict[str,Any]|None) -> dict[str,Any]:
    rdap=rdap if isinstance(rdap,dict) else {}
    events=[x for x in (rdap.get('events') or []) if isinstance(x,dict)]
    entities=[x for x in (rdap.get('entities') or []) if isinstance(x,dict)]
    registrar=_registrar_entity(entities)
    created=_event(events, {'registration','registered','creation'})
    expires=_event(events, {'expiration','expiry','expiration date'})
    updated=_event(events, {'last changed','last update','last changed date','update','updated'})
    age_days=None
    if created:
        try:
            age_days=max(0,(datetime.now(timezone.utc)-datetime.fromisoformat(created.replace('Z','+00:00'))).days)
        except Exception:
            pass
    public_ids=registrar.get('public_ids') or registrar.get('publicIds') or []
    iana_id=None
    for item in public_ids:
        if isinstance(item,dict) and str(item.get('type','')).lower() in {'iana registrar id','iana id','iana'}:
            iana_id=item.get('identifier')
            break
    return {
        'domain': rdap.get('ldh_name') or domain,
        'unicode_domain': rdap.get('unicode_name'),
        'registered_on': created,
        'expires_on': expires,
        'updated_on': updated,
        'status': list(rdap.get('status_codes') or []),
        'name_servers': list(rdap.get('name_servers') or []),
        'domain_age_days': age_days,
        'registrar': {
            'name': registrar.get('name') or registrar.get('organization') or rdap.get('registrar'),
            'iana_id': iana_id or registrar.get('handle'),
            'handle': registrar.get('handle'),
            'abuse_email': registrar.get('abuse_email'),
            'abuse_phone': registrar.get('abuse_phone'),
            'email': registrar.get('email'),
            'phone': registrar.get('phone'),
            'address': registrar.get('address'),
        },
        'registrant': next((x for x in entities if 'registrant' in {str(r).lower() for r in (x.get('roles') or [])}), {}),
        'admin_contacts': [x for x in entities if 'administrative' in {str(r).lower() for r in (x.get('roles') or [])}],
        'technical_contacts': [x for x in entities if 'technical' in {str(r).lower() for r in (x.get('roles') or [])}],
        'events': events,
        'source': rdap.get('source') or 'RDAP',
        'privacy_note': 'Contact/address fields are registry/provider returned only. Privacy redaction is preserved and is not treated as suspicious.',
    }
