from __future__ import annotations
NAME='http_probers'
COUNT=20
DESCRIPTION='Internal http probers capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
