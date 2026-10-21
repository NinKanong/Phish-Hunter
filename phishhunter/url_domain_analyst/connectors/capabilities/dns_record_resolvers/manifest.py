from __future__ import annotations
NAME='dns_record_resolvers'
COUNT=18
DESCRIPTION='Internal dns record resolvers capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
