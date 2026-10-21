from __future__ import annotations
NAME='crawlers'
COUNT=26
DESCRIPTION='Internal crawlers capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
