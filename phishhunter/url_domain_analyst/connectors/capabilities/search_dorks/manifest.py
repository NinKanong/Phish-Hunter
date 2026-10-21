from __future__ import annotations
NAME='search_dorks'
COUNT=10
DESCRIPTION='Internal search dorks capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
