from __future__ import annotations
NAME='technology_fingerprinters'
COUNT=22
DESCRIPTION='Internal technology fingerprinters capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
