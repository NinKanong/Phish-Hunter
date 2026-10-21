from __future__ import annotations
NAME='url_structural_parsers'
COUNT=12
DESCRIPTION='Internal url structural parsers capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
