from __future__ import annotations
NAME='continuous_monitoring'
COUNT=12
DESCRIPTION='Internal continuous monitoring capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
