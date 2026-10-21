from __future__ import annotations
NAME='domain_registry_whois'
COUNT=26
DESCRIPTION='Internal domain registry whois capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
