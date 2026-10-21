from __future__ import annotations

def suggest(result:dict)->list[dict]:
    suggestions=[]; graph=result.get('graph',{}); domain=result.get('domain')
    ips=(result.get('dns',{}).get('records',{}).get('A',[]) or [])+(result.get('dns',{}).get('records',{}).get('AAAA',[]) or [])
    for row in ips[:10]: suggestions.append({'pivot_type':'ip','value':row.get('value'),'reason':'Current DNS resolution','priority':1})
    for ns in result.get('dns_posture',{}).get('records',{}).get('NS',[])[:10]: suggestions.append({'pivot_type':'nameserver','value':ns.get('value'),'reason':'Authoritative infrastructure pivot','priority':2})
    for name in (result.get('certificate_transparency',{}) or {}).get('names',[])[:50]: suggestions.append({'pivot_type':'hostname','value':name,'reason':'Certificate Transparency hostname','priority':2})
    if domain: suggestions.append({'pivot_type':'passive-dns','value':domain,'reason':'Retrieve historical A/AAAA/NS/MX changes from an authorized provider','priority':1})
    return suggestions[:100]
