from __future__ import annotations
NAME='brand_monitoring'
COUNT=14
DESCRIPTION='Internal brand monitoring capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
