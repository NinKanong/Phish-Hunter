from __future__ import annotations
NAME='cookie_analysis'
COUNT=8
DESCRIPTION='Internal cookie analysis capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
