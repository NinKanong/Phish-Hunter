from __future__ import annotations
import hashlib
from ..utils.entropy import shannon
from ..utils.unicode import scripts, invisible_chars, normalized_forms, bidi_flags
from .public_suffix import try_psl

COMMON_MULTI_TLDS={'co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.jp','co.nz','com.sg','com.cn','com.br','com.hk','co.in','org.in','net.in','co.za','com.mx','com.tr','com.tw','com.ar','com.pl','com.ua','com.my','com.ph','com.vn','com.ng'}
PRIVATE_SUFFIXES={'github.io','gitlab.io','pages.dev','vercel.app','netlify.app','herokuapp.com','s3.amazonaws.com','cloudfront.net','azurewebsites.net','appspot.com'}

def registered_domain(domain: str) -> tuple[str,str,str]:
    d=domain.strip().strip('.').lower()
    labels=d.split('.') if d else []
    if len(labels)<=2: return d, labels[-1] if labels else '', labels[0] if labels else ''
    suffix2='.'.join(labels[-2:])
    if suffix2 in COMMON_MULTI_TLDS or suffix2 in PRIVATE_SUFFIXES:
        return '.'.join(labels[-3:]), suffix2, labels[-3]
    return '.'.join(labels[-2:]), labels[-1], labels[-2]

def _label(label: str) -> dict:
    return {'label':label,'length':len(label),'entropy':shannon(label),'digit_ratio':(sum(c.isdigit() for c in label)/len(label) if label else 0),
            'dash_count':label.count('-'),'vowel_ratio':(sum(c.lower() in 'aeiou' for c in label)/len(label) if label else 0),
            'scripts':scripts(label),'mixed_scripts':len(scripts(label))>1,'invisible_chars':invisible_chars(label),
            'bidi_flags':bidi_flags(label),'punycode':label.startswith('xn--'),'sha256':hashlib.sha256(label.encode()).hexdigest()}

def analyze(domain: str) -> dict:
    d=domain.strip().strip('.')
    psl=try_psl(d)
    registered=psl.get('registered_domain') or registered_domain(d)[0]
    tld=psl.get('suffix') or registered_domain(d)[1]
    sld=psl.get('sld') or registered_domain(d)[2]
    labels=d.split('.') if d else []
    sub=list(psl.get('subdomains') or labels[:max(0,len(labels)-len(registered.split('.')))])
    label_rows=[_label(x) for x in labels]
    suspicious=[]
    if any(x['mixed_scripts'] or x['invisible_chars'] or x['bidi_flags'] for x in label_rows): suspicious.append('unicode-confusable')
    if any(x['punycode'] for x in label_rows): suspicious.append('punycode')
    if any(x['entropy'] > 3.6 and x['length'] >= 10 for x in label_rows): suspicious.append('high-entropy-label')
    if any(x['digit_ratio'] > .55 for x in label_rows): suspicious.append('digit-heavy-label')
    return {
      'fqdn':d,'registered_domain':registered,'tld':tld,'sld':sld,'subdomain':'/'.join(sub) if sub else '',
      'subdomain_labels':sub,'subdomain_depth':len(sub),'labels':label_rows,
      'label_count':len(labels),'idn':any(x['punycode'] for x in label_rows) or bool(normalized_forms(d)['NFKC']!=d),
      'scripts':scripts(d),'mixed_scripts':len(scripts(d))>1,'invisible_chars':invisible_chars(d),'bidi_flags':bidi_flags(d),
      'suspicious_domain_signals':sorted(set(suspicious)),'hashes':{'sha256':hashlib.sha256(d.encode()).hexdigest()},
      'psl':{'match_type':psl.get('method','fallback'),'matched_suffix':tld,'note':'Uses an installed Public Suffix List library when available; otherwise uses the curated fallback.'},
      'private_suffix':registered.lower().endswith(tuple(PRIVATE_SUFFIXES)),
      'field_contract':{**{f'field_{i:03d}':None for i in range(1,121)},'field_map_version':'domain-120-vnext'}
    }
