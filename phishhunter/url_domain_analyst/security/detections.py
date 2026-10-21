from __future__ import annotations
import difflib, math, re
from ..utils.entropy import shannon
from ..domain.anatomy import registered_domain

LOOKALIKE_MAP=str.maketrans({'0':'o','1':'l','3':'e','5':'s','7':'t','8':'b'})

def _edit(a,b): return difflib.SequenceMatcher(None,a,b).ratio()

def typosquat_candidates(domain:str, brands:list[str]|None=None, max_items:int=100) -> list[dict]:
    reg=registered_domain(domain)[0]; brands=brands or []
    candidates=[]
    base=reg.split('.')[0]
    for brand in brands:
        b=brand.lower().replace(' ','')
        for variant,tech in [(b[:-1],'omission'),(b+'a','insertion'),(b.replace('o','0'),'homoglyph/number'),(b.replace('-',''),'hyphenation')]:
            if variant and variant != base:
                candidates.append({'candidate':variant+'.'+reg.split('.',1)[-1],'algorithm':tech,'similarity':round(_edit(base,variant),4)})
    return sorted(candidates,key=lambda x:x['similarity'],reverse=True)[:max_items]

def homograph_assessment(value:str)->dict:
    normalized=value.translate(LOOKALIKE_MAP)
    score=min(100, int(_edit(value,normalized)*100))
    return {'value':value,'skeleton':normalized,'similarity_score':score,'scripts_mixed':len({c.isascii() for c in value if c.isalpha()})>1}

def dga_score(label:str)->dict:
    if not label: return {'score':0,'signals':[]}
    vowels=sum(c.lower() in 'aeiou' for c in label); digits=sum(c.isdigit() for c in label)
    score=0; sig=[]
    if len(label)>=12: score+=20; sig.append('long-label')
    if shannon(label)>=3.2: score+=30; sig.append('high-entropy')
    if vowels/max(1,len(label)) < .18: score+=15; sig.append('low-vowel-ratio')
    if digits/max(1,len(label)) > .45: score+=20; sig.append('digit-heavy')
    if '-' in label: score+=5; sig.append('dash')
    return {'score':min(score,100),'signals':sig,'heuristic_only':True}

def dns_tunnel_score(subdomains:list[str], txt_values:list[str]|None=None)->dict:
    txt_values=txt_values or []
    lengths=[len(x) for x in subdomains]; entropies=[shannon(x) for x in subdomains]
    score=0; sig=[]
    if lengths and sum(lengths)/len(lengths)>35: score+=30; sig.append('long-subdomain-average')
    if entropies and sum(entropies)/len(entropies)>3.4: score+=30; sig.append('high-entropy-subdomains')
    if any(len(x)>200 for x in txt_values): score+=20; sig.append('large-txt-record')
    return {'score':min(score,100),'signals':sig,'evidence_limit':'Heuristic only; volume/time-series data is required for confident DNS tunneling claims.'}

def takeover_candidates(dns_records:dict)->list[dict]:
    out=[]
    for row in dns_records.get('CNAME',[]) or []:
        value=str(row.get('value') or '')
        if value and any(x in value.lower() for x in ('github.io','s3.amazonaws.com','herokuapp.com','azurewebsites.net','cloudfront.net','vercel.app','netlify.app')):
            out.append({'cname':value,'service':'managed-hosting','risk':'requires-verification','reason':'CNAME points to a provider commonly associated with takeover checks.'})
    return out
