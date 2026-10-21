from __future__ import annotations
NAME='search_engine_discovery'
COUNT=12
DESCRIPTION='Internal search engine discovery capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
