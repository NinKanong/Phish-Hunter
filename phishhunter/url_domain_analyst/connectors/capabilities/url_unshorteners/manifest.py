from __future__ import annotations
NAME='url_unshorteners'
COUNT=14
DESCRIPTION='Internal url unshorteners capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
