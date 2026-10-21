from __future__ import annotations
NAME='geoip_asn'
COUNT=12
DESCRIPTION='Internal geoip asn capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
