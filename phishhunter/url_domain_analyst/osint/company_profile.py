from __future__ import annotations
from typing import Any


def build(domain:str, wappalyzer:dict[str,Any]|None=None, rdap:dict[str,Any]|None=None)->dict[str,Any]:
    w=wappalyzer if isinstance(wappalyzer,dict) else {}
    c=w.get('company') if isinstance(w.get('company'),dict) else {}
    r=rdap if isinstance(rdap,dict) else {}
    entities=[x for x in (r.get('entities') or []) if isinstance(x,dict)]
    organizations=[]
    contacts=[]
    jurisdictions=[]
    for e in entities:
        org=e.get('organization')
        if org: organizations.append(str(org))
        if e.get('email'): contacts.append({'type':'email','value':e.get('email'),'role':e.get('roles')})
        addr=e.get('address')
        if isinstance(addr,dict):
            for key in ('country','countryCode','city','region'):
                if addr.get(key): jurisdictions.append({'field':key,'value':addr.get(key)})
        elif isinstance(addr,list):
            text=' '.join(str(x) for x in addr)
            if text: jurisdictions.append({'field':'address','value':text[:500]})
    return {
      'domain':domain,'company_name':c.get('name') or c.get('inferred_name') or (organizations[0] if organizations else None),
      'industry':c.get('industry'),'type':c.get('company_type'),'about':c.get('about'),'founded':c.get('company_founded'),
      'employee_size_range':c.get('company_size'),'locations':c.get('locations') or [],'linkedin':c.get('linkedin') or [],
      'organizations':sorted(set(organizations)),'registration_jurisdictions':jurisdictions[:50],
      'public_contact_count':len(contacts),'public_contacts':contacts[:100],
      'limits':'Company and workforce fields are provider-backed or RDAP-backed; absence does not imply the company has no employees or contacts.'
    }
