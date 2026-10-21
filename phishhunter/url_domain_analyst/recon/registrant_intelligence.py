from __future__ import annotations
from typing import Any

FIELDS = [
    'name','organization','email','phone','fax','street','city','state','postal_code','country','contact_id','handle','roles',
    'privacy_provider','privacy_reason','redaction_level','redacted_name','redacted_org','redacted_email','redacted_phone','redacted_address',
    'contact_form','abuse_contact','historical_name','historical_org','historical_email','historical_phone','historical_country','historical_address',
    'reverse_whois_count','reverse_whois_domains','reverse_whois_confidence','entity_type','legal_entity','jurisdiction','company_id',
    'tax_id','incorporation_date','company_status','industry','sic_code','naics_code','employee_count','revenue','funding','investors',
    'founders','executives','linkedin','website','social_profiles','related_domains','related_ips','related_asns','related_certs',
    'related_emails','source_count','source_consensus','observed_at','evidence_ids','confidence','privacy_note'
]

def _flat(v: Any, prefix='') -> dict[str,Any]:
    out={}
    if isinstance(v,dict):
        for k,x in v.items():
            key=f'{prefix}.{k}' if prefix else str(k)
            if isinstance(x,dict): out.update(_flat(x,key))
            else: out[key.lower()]=x
    return out

def _value(flat:dict[str,Any], name:str):
    for k in (name,f'registrant.{name}',f'contact.{name}'):
        if k.lower() in flat and flat[k.lower()] not in (None,'',[],{}): return flat[k.lower()]
    return None

def build(domain_info:dict[str,Any], rdap:dict[str,Any]|None=None, company:dict[str,Any]|None=None,
          attack_surface:dict[str,Any]|None=None, graph:dict[str,Any]|None=None, ct:dict[str,Any]|None=None) -> dict[str,Any]:
    di=domain_info if isinstance(domain_info,dict) else {}; rdap=rdap or {}; company=company or {}; surface=attack_surface or {}; graph=graph or {}; ct=ct or {}
    reg=di.get('registrant') if isinstance(di.get('registrant'),dict) else {}
    flat=_flat(reg)
    entities=[x for x in (rdap.get('entities') or []) if isinstance(x,dict)]
    if not reg:
        for e in entities:
            if 'registrant' in {str(r).lower() for r in (e.get('roles') or [])}:
                reg=e; flat=_flat(e); break
    observed=[]
    for f in FIELDS:
        val=_value(flat,f)
        observed.append({'field':f.replace('_',' ').title(),'key':f,'value':val,'status':'observed' if val not in (None,'',[],{}) else 'not-observed',
                         'source':'RDAP/WHOIS/provider' if val not in (None,'',[],{}) else 'provider-dependent','confidence':'source-backed' if val not in (None,'',[],{}) else None})
    redacted=[x['key'] for x in observed if x['key'].startswith('redacted_') and x['status']=='observed']
    direct={x['key']:x['value'] for x in observed if x['status']=='observed'}
    privacy=direct.get('privacy_provider') or direct.get('privacy_reason') or any(x['key'].startswith('redacted_') and x['status']=='observed' for x in observed)
    # Correlations are only surfaced when returned by evidence; they are not inferred from name similarity.
    related_domains=list(dict.fromkeys([str(x.get('host')) for x in (surface.get('a_records') or []) if isinstance(x,dict) and x.get('host')]))[:500]
    related_ips=list(dict.fromkeys([str(x.get('ip')) for x in (surface.get('a_records') or []) if isinstance(x,dict) and x.get('ip')]))[:500]
    related_asns=list(dict.fromkeys([str(x.get('asn')) for x in (surface.get('a_records') or []) if isinstance(x,dict) and x.get('asn')]))[:200]
    cert_names=list(dict.fromkeys([str(x) for x in (ct.get('discovered_names') or []) if x]))[:500]
    graph_neighbors=[]
    root=f"domain:{di.get('domain') or ''}"
    for e in graph.get('edges') or []:
        if isinstance(e,dict) and (e.get('source')==root or e.get('target')==root): graph_neighbors.append(e)
    summary={
      'identity_state':'observed' if any(x['status']=='observed' for x in observed) else 'not-observed',
      'privacy_state':'redacted/privacy service observed' if privacy else 'no privacy indicator observed',
      'observed_field_count':sum(x['status']=='observed' for x in observed), 'field_count':len(observed),
      'redacted_field_count':len(redacted),'rdap_entity_count':len(entities),
      'relationship_count':len(graph_neighbors),'related_domain_count':len(related_domains),'related_ip_count':len(related_ips),
      'related_asn_count':len(related_asns),'certificate_name_count':len(cert_names),
      'source_count':1 if observed and any(x['status']=='observed' for x in observed) else 0,
      'consensus':'single-provider' if observed and any(x['status']=='observed' for x in observed) else 'not-established',
    }
    hypotheses=[]
    if privacy: hypotheses.append({'type':'privacy','statement':'Registry/provider redaction or privacy service is present; redaction is not treated as suspicious.','confidence':'evidence-backed'})
    if related_domains: hypotheses.append({'type':'relationship','statement':f'{len(related_domains)} host relationships were already present in the case attack-surface evidence.','confidence':'case-evidence'})
    if not any(x['status']=='observed' for x in observed): hypotheses.append({'type':'coverage','statement':'Registrant identity is not exposed by the current provider set.','confidence':'coverage-state'})
    return {'version':'DOMINUS-REGISTRANT-2','target':di.get('domain'),'profile':direct,'fields':observed,'summary':summary,
            'privacy':{'detected':bool(privacy),'redacted_fields':redacted,'treatment':'privacy/redaction is preserved and never interpreted as malicious'},
            'correlations':{'domains':related_domains,'ips':related_ips,'asns':related_asns,'certificate_names':cert_names,'graph_neighbors':graph_neighbors[:200],
                            'company_evidence':company.get('name') or company.get('company_name')},
            'hypotheses':hypotheses,'next_pivots':['Historical RDAP/WHOIS provider','Authorized reverse-WHOIS dataset','Corporate registry correlation','Certificate and DNS relationship correlation'],
            'evidence_boundary':'Only registry/provider-returned or already-observed case relationships are shown. No private-person identity is inferred.'}
