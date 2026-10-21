from __future__ import annotations
NAME='javascript_analysis'
COUNT=20
DESCRIPTION='Internal javascript analysis capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
