from __future__ import annotations
NAME='certificate_search'
COUNT=10
DESCRIPTION='Internal certificate search capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
