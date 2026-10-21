from __future__ import annotations
NAME='rdap_providers'
COUNT=10
DESCRIPTION='Internal rdap providers capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
