from __future__ import annotations
from collections import defaultdict
from ..contracts.models import Entity, Relationship, InvestigationPackage
from ..contracts.enums import NodeKind, EdgeKind


def _id(kind:str,label:str)->str: return f'{kind}:{label}'.lower()

def build(result:dict) -> dict:
    domain=result.get('domain') or result.get('registered_domain') or result.get('target') or ''
    pkg=InvestigationPackage(target=str(result.get('target') or domain))
    def entity(kind,label,props=None,evidence_ids=None):
        eid=_id(kind,label); pkg.entities.append(Entity(eid,kind,label,props or {},evidence_ids or [])); return eid
    def edge(src,dst,kind,confidence=.9,props=None):
        rid=f'{kind}:{src}:{dst}'; pkg.relationships.append(Relationship(rid,src,dst,kind,confidence,properties=props or {}))
    d=entity(NodeKind.DOMAIN,domain,{'registered_domain':result.get('registered_domain')})
    u=entity(NodeKind.URL,str(result.get('url') or domain),{'target':True})
    edge(u,d,EdgeKind.PART_OF,.98)
    dns=(result.get('dns') or {}).get('records',{}) or {}
    for r in dns.get('A',[])[:50]:
        ip=str(r.get('value') or '');
        if ip: edge(d,entity(NodeKind.IP,ip,{'ttl':r.get('ttl')}),EdgeKind.RESOLVES_TO,.97)
    for r in dns.get('AAAA',[])[:50]:
        ip=str(r.get('value') or '');
        if ip: edge(d,entity(NodeKind.IP,ip,{'ttl':r.get('ttl')}),EdgeKind.RESOLVES_TO,.97)
    for r in dns.get('CNAME',[])[:50]:
        v=str(r.get('value') or '');
        if v: edge(d,entity(NodeKind.SUBDOMAIN,v,{'record':'CNAME'}),EdgeKind.CNAME_TO,.95)
    for r in dns.get('NS',[])[:50]:
        v=str(r.get('value') or '');
        if v: edge(d,entity(NodeKind.NS,v,{}),EdgeKind.NS_OF,.95)
    for r in dns.get('MX',[])[:50]:
        v=str(r.get('value') or '');
        if v: edge(d,entity(NodeKind.MX,v,{}),EdgeKind.MX_OF,.95)
    for cert in (result.get('certificate_transparency') or {}).get('certificates',[])[:100]:
        fp=str(cert.get('sha256_fingerprint') or cert.get('fingerprint') or ''); label=fp or str(cert.get('serial') or 'certificate')
        c=entity(NodeKind.CERT,label,cert)
        edge(c,d,EdgeKind.ISSUED_FOR,.94)
        for san in (cert.get('san') or [])[:40]: edge(c,entity(NodeKind.SUBDOMAIN,str(san),{}),EdgeKind.ISSUED_FOR,.9)
    for tech in (result.get('technology') or [])[:50]:
        label=str(tech.get('name') if isinstance(tech,dict) else tech); edge(d,entity(NodeKind.TECHNOLOGY,label,{}),EdgeKind.HAS_TECH,.8)
    for r in (result.get('http') or {}).get('redirects',[])[:50]:
        loc=str(r.get('location') or r.get('url') or '');
        if loc: edge(u,entity(NodeKind.REDIRECT,loc,r),EdgeKind.REDIRECTS_TO,.92)
    return {'nodes':[{'id':e.entity_id,'kind':e.kind,'label':e.label,'properties':e.properties} for e in pkg.entities],
            'edges':[{'id':x.relationship_id,'source':x.source_id,'target':x.target_id,'kind':x.kind,'confidence':x.confidence,'properties':x.properties} for x in pkg.relationships],
            'node_count':len(pkg.entities),'edge_count':len(pkg.relationships),'package_sha256':pkg.sha256(),
            'graph_model':{'layout_modes':['force','hierarchical','radial','timeline','geographic'],'edge_types':[e.value for e in EdgeKind]},
            'interaction_contract':{'drag_nodes':True,'pan_canvas':True,'zoom':True,'click_to_isolate':True,'shortest_path':True,'one_hop':True,'two_hop':True}}
