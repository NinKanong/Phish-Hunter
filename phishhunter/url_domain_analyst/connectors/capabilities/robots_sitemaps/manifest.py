from __future__ import annotations
NAME='robots_sitemaps'
COUNT=8
DESCRIPTION='Internal robots sitemaps capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
