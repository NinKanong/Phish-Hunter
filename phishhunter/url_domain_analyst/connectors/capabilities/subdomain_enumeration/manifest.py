from __future__ import annotations
NAME='subdomain_enumeration'
COUNT=42
DESCRIPTION='Internal subdomain enumeration capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
