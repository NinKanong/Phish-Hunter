from __future__ import annotations
NAME='url_reputation'
COUNT=28
DESCRIPTION='Internal url reputation capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
