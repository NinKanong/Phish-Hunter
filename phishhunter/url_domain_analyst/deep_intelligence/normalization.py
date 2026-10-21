from __future__ import annotations
import hashlib, ipaddress, re
from urllib.parse import urlparse

_HOST_RE=re.compile(r"^[A-Za-z0-9._:-]+$")

def normalize_target(target: str)->dict:
    raw=(target or '').strip()
    if not raw: raise ValueError('A domain or URL is required before starting the investigation.')
    candidate=raw if '://' in raw else 'https://'+raw
    p=urlparse(candidate)
    host=(p.hostname or '').rstrip('.').strip().lower()
    if not host: raise ValueError('The target does not contain a valid hostname.')
    try:
        ip=ipaddress.ip_address(host)
        host_type='ipv4' if ip.version==4 else 'ipv6'
        registered=host
    except ValueError:
        host_type='fqdn'
        try: host=host.encode('idna').decode('ascii')
        except UnicodeError: pass
        labels=[x for x in host.split('.') if x]
        registered='.'.join(labels[-2:]) if len(labels)>=2 else host
    url=candidate if p.scheme in {'http','https'} else f'https://{host}/'
    return {'raw':raw,'normalized_url':url,'hostname':host,'registered_domain':registered,'host_type':host_type,'is_url':bool(p.scheme in {'http','https'}),'sha256':hashlib.sha256(raw.encode()).hexdigest()}
