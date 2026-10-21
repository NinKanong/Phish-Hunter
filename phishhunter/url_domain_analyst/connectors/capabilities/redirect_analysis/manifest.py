from __future__ import annotations
NAME='redirect_analysis'
COUNT=10
DESCRIPTION='Internal redirect analysis capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
