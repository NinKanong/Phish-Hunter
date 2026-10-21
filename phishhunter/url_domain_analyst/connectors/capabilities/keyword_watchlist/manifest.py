from __future__ import annotations
NAME='keyword_watchlist'
COUNT=10
DESCRIPTION='Internal keyword watchlist capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
