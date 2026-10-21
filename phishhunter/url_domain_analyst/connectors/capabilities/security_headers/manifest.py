from __future__ import annotations
NAME='security_headers'
COUNT=10
DESCRIPTION='Internal security headers capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
