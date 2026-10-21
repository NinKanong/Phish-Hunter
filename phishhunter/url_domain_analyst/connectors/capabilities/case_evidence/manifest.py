from __future__ import annotations
NAME='case_evidence'
COUNT=10
DESCRIPTION='Internal case evidence capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
