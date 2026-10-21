from __future__ import annotations
import ipaddress

def lookup(ip):
    try: scope='private' if ipaddress.ip_address(ip).is_private else 'public' if ipaddress.ip_address(ip).is_global else 'special'
    except ValueError: scope='unknown'
    return {'ip':ip,'scope':scope,'country':None,'asn':None,'isp':None,'status':'local-classification-only'}
