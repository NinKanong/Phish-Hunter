from __future__ import annotations
NAME='blocklists_feeds'
COUNT=24
DESCRIPTION='Internal blocklists feeds capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
