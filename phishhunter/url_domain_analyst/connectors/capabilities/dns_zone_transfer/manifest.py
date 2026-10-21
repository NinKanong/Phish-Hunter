from __future__ import annotations
NAME='dns_zone_transfer'
COUNT=6
DESCRIPTION='Internal dns zone transfer capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
