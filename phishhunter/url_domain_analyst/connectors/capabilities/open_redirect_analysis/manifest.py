from __future__ import annotations
NAME='open_redirect_analysis'
COUNT=6
DESCRIPTION='Internal open redirect analysis capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
