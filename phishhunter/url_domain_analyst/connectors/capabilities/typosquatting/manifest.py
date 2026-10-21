from __future__ import annotations
NAME='typosquatting'
COUNT=18
DESCRIPTION='Internal typosquatting capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
