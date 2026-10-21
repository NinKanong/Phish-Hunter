from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from .catalog import CATEGORIES, build_source_catalog, source_catalog_stats
from .fields import field_catalog
from .direct_links import build_direct_links

CATEGORY_PIVOTS={
 'search_engine':['domain→indexed URLs','domain→public documents','domain→API references','domain→login references'],
 'social_media':['domain→organization profiles','organization→public roles','brand→impersonation candidates','profile→public links'],
 'code_repository':['domain→repositories','repository→contributors','repository→endpoints','repository→secret indicators'],
 'documents_files':['domain→PDF/DOCX/XLSX/PPTX','document→metadata','document→archive snapshots','document→related entities'],
 'image_media':['domain→media URLs','image→reverse matches','image→EXIF','image→archive occurrences'],
 'email_identity':['domain→public email addresses','email→provider reputation','email→authorized breach provider','email→public profiles'],
 'corporate_business':['domain→legal entity','entity→registries','entity→officers','entity→locations'],
 'people':['public name→username','username→public profiles','public profile→repositories','public record→entity correlation'],
 'domain_dns':['domain→passive DNS','domain→certificates','subdomain→IP','IP→ASN'],
 'threat_intel':['domain→reputation feeds','IP→threat feeds','IOC→campaign context','IOC→MITRE context'],
 'breach_exposure':['email→breach providers','domain→exposure providers','identifier→data classes','exposure→remediation'],
 'dark_web':['keyword→authorized dark-web feed','domain→authorized feed','brand→mention feed','indicator→threat context'],
 'geospatial':['IP→GeoIP','entity→public locations','media→EXIF coordinates','location→map context'],
 'financial_crypto':['entity→public financial records','address→blockchain explorer','entity→sanctions','transaction→counterparty'],
 'legal_public_records':['entity→registries','entity→sanctions','entity→court records','entity→debarment/licensing'],
}

def _flatten(obj: Any, prefix=''):
    if isinstance(obj,dict):
        for k,v in obj.items():
            key=f'{prefix}.{k}' if prefix else str(k)
            yield key.lower(),v
            yield from _flatten(v,key)
    elif isinstance(obj,list):
        for i,v in enumerate(obj[:100]): yield from _flatten(v,f'{prefix}[{i}]')

def _observed_for_field(field:str, result:dict, category:str):
    """Best-effort alias matching against actual case evidence; never creates a value."""
    aliases={
      'domain':['domain','registered_domain','fqdn'],'url':['url','target'],'email':['email','emails'],'country':['country','country_code'],'country_code':['country_code'],'latitude':['lat','latitude'],'longitude':['lon','lng','longitude'],
      'organization':['organization','org','asn_name','company'],'legal_name':['legal_name','company_name'],'company':['company','company_name'],'employees':['employees','employee_count'],'repository':['repository','repo'],'repository_url':['repository_url','repo_url'],'ip':['ip','address'],'asn':['asn','as_number'],'source_url':['source_url','url'],'http_status':['http_status','status_code'],'mime_type':['mime_type','content_type'],'title':['title'],'description':['description'],'author':['author'],'created':['created','created_at'],'modified':['modified','modified_at'],'sha256':['sha256','content_hash'],'confidence':['confidence']
    }
    keys=aliases.get(field.lower(),[field.lower()])
    flat=list(_flatten(result))
    for path,val in flat:
        leaf=path.rsplit('.',1)[-1].split('[')[0]
        if leaf in keys and val not in (None,'',[],{}):
            return val, path
    return None, None

def _ai(field:str,value:Any,source:str)->dict:
    if value is None:
        return {'status':'no-evidence','insight':'No source-backed observation for this field.','confidence':0,'anomaly':'not-assessed','prediction':'not-generated'}
    return {'status':'evidence-grounded','insight':f'Observed from {source}; review provenance before disposition.','confidence':'source-derived','anomaly':'not-assessed','prediction':'not-generated'}

def build_advanced_osint(result:dict, domain:str, ips:list[str]|None=None, graph:dict|None=None)->dict:
    ips=ips or []
    sources=build_source_catalog(360)
    fields=field_catalog()
    direct_links=build_direct_links(domain)
    observed=[]
    for f in fields:
        val,path=_observed_for_field(f['field'],result,f['category'])
        source=path.split('.')[0] if path else 'not-observed'
        row={**f,'value':val,'observed':val is not None,'status':'observed' if val is not None else 'not-observed','source':source,'provenance':path,'ai':_ai(f['field'],val,source)}
        observed.append(row)
    pivots=[]
    for category,title,count in CATEGORIES:
        for action in CATEGORY_PIVOTS.get(category,[])[:3]:
            pivots.append({'id':f'pivot.{len(pivots)+1:04d}','category':category,'title':title,'action':action,'target':domain,'status':'ready' if category in ('domain_dns','search_engine','documents_files') else 'provider-dependent','priority':1 if category in ('domain_dns','threat_intel','search_engine') else 2,'requires_authorized_source':category in ('breach_exposure','dark_web','people','social_media','financial_crypto','legal_public_records')})
    categories=[]
    for k,t,c in CATEGORIES:
        cat_obs=sum(1 for row in observed if row['category']==k and row['observed'])
        categories.append({'id':k,'name':t,'fields':c,'source_contracts':sum(1 for src in sources if src['category']==k),'observed_fields':cat_obs,'direct_link_count':len(direct_links.get(k,[]))})
    return {
      'version':'DOMINUS-ADVANCED-OSINT-V29','category_count':len(CATEGORIES),'categories':categories,
      'field_count':len(fields),'observed_field_count':sum(1 for x in observed if x['observed']),'fields':observed,
      'source_catalog':sources,'source_stats':source_catalog_stats(sources),'pivot_count':len(pivots),'pivots':pivots,
      'direct_links':direct_links,'direct_link_count':sum(len(v) for v in direct_links.values()),
      'pivot_chains':[{'id':i+1,'category':k,'chain':CATEGORY_PIVOTS.get(k,[]) } for i,(k,_,_) in enumerate(CATEGORIES)],
      'graph_context':{'nodes':len((graph or {}).get('nodes') or []),'edges':len((graph or {}).get('edges') or [])},
      'collection_policy':'Public/authorized/provider evidence only. No scraping bypass, credential testing, direct dark-web crawling, or private identity inference.',
      'generated_at':datetime.now(timezone.utc).isoformat(),
      'target':domain,'ip_targets':ips[:100],
    }
