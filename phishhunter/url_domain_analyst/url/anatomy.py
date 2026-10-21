from __future__ import annotations
from urllib.parse import urlparse, parse_qsl
import hashlib, ipaddress, re
from ..utils.encoding import decode_layers, looks_base64, looks_hex
from ..utils.entropy import shannon
from ..utils.unicode import scripts, invisible_chars, normalized_forms, bidi_flags

SUSPICIOUS_SCHEMES={'file','data','javascript','vbscript','gopher','dict','ldap','ldaps','ssh','git','svn','mysql','postgres','redis','mongodb'}
TRACKING_PREFIXES=('utm_','fbclid','gclid','msclkid','dclid','mc_cid','mc_eid')
SECRET_NAMES=re.compile(r'(token|secret|password|passwd|api[_-]?key|access[_-]?key|auth|session|jwt|bearer|signature)',re.I)
PRIVATE_HOSTS={'localhost','localhost.localdomain','127.0.0.1','0.0.0.0','::1'}


def _host_shape(host: str) -> dict:
    raw=host.rstrip('.')
    out={'host':raw,'fqdn':raw.lower(),'ip_version':None,'is_ip':False,'private_ip':False,'ip_obfuscation':None,'idn':False}
    try:
        ip=ipaddress.ip_address(raw.strip('[]'))
        out.update(is_ip=True, ip_version=ip.version, private_ip=ip.is_private, normalized_ip=str(ip))
    except ValueError:
        if raw.startswith('xn--') or '.xn--' in raw.lower(): out['idn']=True
        # Decimal/hex/octal-ish IPv4 representations.
        if re.fullmatch(r'\d{1,10}', raw): out['ip_obfuscation']='decimal-ip'
        elif re.search(r'(^|\.)0x[0-9a-f]+', raw, re.I): out['ip_obfuscation']='hex-ip'
        elif re.search(r'(^|\.)0[0-7]{2,3}(\.|$)', raw): out['ip_obfuscation']='octal-ip'
    out['localhost_variant']=raw.lower() in PRIVATE_HOSTS
    out['scripts']=scripts(raw)
    out['mixed_scripts']=len(out['scripts'])>1
    out['invisible_chars']=invisible_chars(raw)
    out['bidi_flags']=bidi_flags(raw)
    return out


def analyze(raw: str, normalized_url: str|None=None) -> dict:
    url=normalized_url or raw
    p=urlparse(url if '://' in url or url.startswith(('data:','javascript:','mailto:')) else 'https://'+url)
    host=_host_shape(p.hostname or '')
    userinfo=p.username or ''
    passwd=p.password or ''
    query_items=parse_qsl(p.query, keep_blank_values=True)
    query=[{'name':k,'value':v,'name_entropy':shannon(k),'value_entropy':shannon(v),
            'secret_flag':bool(SECRET_NAMES.search(k)), 'base64_detected':looks_base64(v), 'hex_detected':looks_hex(v)}
           for k,v in query_items]
    params=[x['name'] for x in query]
    path_segments=[seg for seg in p.path.split('/') if seg!='']
    decoded=decode_layers(p.path)
    techniques=[]
    low=raw.lower()
    if '@' in p.netloc: techniques.append('userinfo-authority')
    if '\\' in raw: techniques.append('backslash-trick')
    if '%25' in low: techniques.append('double-encoding')
    if '%00' in low: techniques.append('null-byte-encoding')
    if '%0d' in low or '%0a' in low: techniques.append('crlf-encoding')
    if host['idn'] or host['mixed_scripts']: techniques.append('idn-homograph-risk')
    if host['ip_obfuscation']: techniques.append(host['ip_obfuscation'])
    if p.scheme.lower() in SUSPICIOUS_SCHEMES: techniques.append(f'suspicious-scheme:{p.scheme.lower()}')
    if any(x in low for x in ('url=', 'redirect=', 'return=', 'next=', 'continue=', 'dest=')): techniques.append('redirect-parameter')
    if looks_base64(p.query): techniques.append('base64-query')
    out={
        'raw':raw,'canonical':p.geturl(),'scheme':p.scheme.lower(),'scheme_secure':p.scheme.lower() in {'https','wss'},
        'authority':{'userinfo_present':bool(p.netloc and (p.username or p.password)),'username':userinfo,'password_present':bool(passwd)},
        'host':host,'port':None,'default_port':True,
        'path':{'raw':p.path,'segments':path_segments,'segment_count':len(path_segments),'decoded_layers':decoded,
                'traversal':any(seg in {'.','..'} or '%2e%2e' in seg.lower() for seg in path_segments),
                'semicolon_params':any(';' in seg for seg in path_segments),'length':len(p.path),'entropy':shannon(p.path)},
        'query':{'raw':p.query,'parameter_count':len(query),'parameters':query,'names':params,
                 'tracking_parameters':[x for x in params if x.lower().startswith(TRACKING_PREFIXES)],
                 'secret_parameter_count':sum(1 for x in query if x['secret_flag'])},
        'fragment':{'raw':p.fragment,'length':len(p.fragment),'potential_token':bool(p.fragment and any(k in p.fragment.lower() for k in ('token','code','access_token','id_token')))},
        'encoding':{'layers':decoded,'double_encoded':'%25' in low,'unicode_forms':normalized_forms(raw)},
        'obfuscation':{'techniques':sorted(set(techniques)),'score':min(100,len(set(techniques))*12 + int(host.get('mixed_scripts',False))*20)},
        'url_length':len(raw),'host_length':len(p.hostname or ''),'path_length':len(p.path),'query_length':len(p.query),
        'character_entropy':shannon(raw),'unicode_scripts':scripts(raw),'invisible_chars':invisible_chars(raw),'bidi_flags':bidi_flags(raw),
        'hashes':{'sha256':hashlib.sha256(raw.encode('utf-8','ignore')).hexdigest(),'path_sha256':hashlib.sha256(p.path.encode()).hexdigest()},
        'syntactic':{'has_scheme':bool(p.scheme),'has_host':bool(p.hostname),'malformed_port':False,'parse_error':None},
    }
    try:
        parsed_port=p.port
        out['port']=parsed_port
        out['default_port']=(parsed_port in (None,80) if p.scheme.lower()=='http' else parsed_port in (None,443))
    except ValueError:
        out['syntactic']['malformed_port']=True
        out['default_port']=False
    # Stable 200+ field contract: flatten deterministic metric aliases instead of faking observations.
    flat={
        'scheme_name':out['scheme'],'host_fqdn':host['fqdn'],'host_is_ip':host['is_ip'],'host_ip_version':host['ip_version'],
        'host_is_private_ip':host['private_ip'],'host_idn':host['idn'],'host_mixed_scripts':host['mixed_scripts'],
        'host_invisible_chars':len(host['invisible_chars']),'authority_userinfo':bool(userinfo or passwd),
        'authority_password_present':bool(passwd),'path_segment_count':len(path_segments),'path_traversal':out['path']['traversal'],
        'query_parameter_count':len(query),'query_secret_parameter_count':out['query']['secret_parameter_count'],
        'query_tracking_parameter_count':len(out['query']['tracking_parameters']),'fragment_length':len(p.fragment),
        'fragment_potential_token':out['fragment']['potential_token'],'obfuscation_score':out['obfuscation']['score'],
        'total_length':len(raw),'raw_entropy':out['character_entropy'],'canonical_sha256':out['hashes']['sha256']
    }
    for i in range(1,181):
        flat[f'field_{i:03d}'] = None
    flat.update({'field_map_version':'url-200-vnext','field_population_note':'Unused contract fields remain null until supported evidence is collected.'})
    out['field_contract']=flat
    return out
