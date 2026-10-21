from __future__ import annotations
from typing import Any


def normalize_entity(entity:dict[str,Any]|None) -> dict[str,Any]:
    e=entity if isinstance(entity,dict) else {}
    address=e.get('address')
    if isinstance(address,dict):
        addr=address
    elif isinstance(address,list):
        vals=[str(x) for x in address if x]
        addr={'formatted':' '.join(vals)} if vals else {}
    else:
        addr={}
    return {
        'name':e.get('name'), 'organization':e.get('organization'),
        'street':addr.get('street') or addr.get('streetAddress'),
        'city':addr.get('city'), 'state':addr.get('state') or addr.get('region'),
        'postal_code':addr.get('postal_code') or addr.get('postalCode'),
        'country':addr.get('country'), 'country_code':addr.get('countryCode'),
        'phone':e.get('phone'), 'email':e.get('email'), 'roles':e.get('roles') or [],
        'handle':e.get('handle'), 'public_ids':e.get('public_ids') or [],
    }
