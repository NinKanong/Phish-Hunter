from __future__ import annotations
NAME='subdomain_takeover'
COUNT=14
DESCRIPTION='Internal subdomain takeover capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
