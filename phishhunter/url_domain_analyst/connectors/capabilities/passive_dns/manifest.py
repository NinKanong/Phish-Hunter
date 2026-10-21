from __future__ import annotations
NAME='passive_dns'
COUNT=24
DESCRIPTION='Internal passive dns capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
