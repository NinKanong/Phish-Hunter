from __future__ import annotations
NAME='ml_models'
COUNT=16
DESCRIPTION='Internal ml models capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
