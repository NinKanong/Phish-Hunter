from __future__ import annotations
import string

KEYBOARD={
 'q':'was','w':'qased','e':'wsdr','r':'edft','t':'rfgy','y':'tghu','u':'yhji','i':'ujko','o':'iklp','p':'ol',
 'a':'qwsz','s':'awedxz','d':'serfcx','f':'drtgvc','g':'ftyhbv','h':'gyujnb','j':'huikmn','k':'jiolm','l':'kop',
 'z':'asx','x':'zsdc','c':'xdfv','v':'cfgb','b':'vghn','n':'bhjm','m':'njk'}

def candidates(domain: str, max_count:int=250):
    labels=domain.split('.')
    if not labels: return []
    sld=labels[-2] if len(labels)>=2 else labels[0]
    suffix='.'.join(labels[-2:]) if len(labels)>=2 else ''
    out=[]
    def add(v,tech):
        if v and v!=domain and '.' in v and v not in {x['domain'] for x in out}: out.append({'domain':v,'technique':tech})
    for i in range(len(sld)):
        add(sld[:i]+sld[i+1:]+'.'+suffix,'omission')
        for repl in KEYBOARD.get(sld[i].lower(),'')[:3]:
            add(sld[:i]+repl+sld[i+1:]+'.'+suffix,'keyboard-substitution')
    for i in range(len(sld)+1): add(sld[:i]+sld[i: i+1]+'.'+suffix,'insertion')
    for i in range(len(sld)-1):
        x=list(sld); x[i],x[i+1]=x[i+1],x[i]; add(''.join(x)+'.'+suffix,'transposition')
    for tld in ('com','net','org','info','io','co','app','dev'):
        if tld!=labels[-1]: add(sld+'.'+tld,'tld-swap')
    return out[:max_count]
