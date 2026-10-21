from __future__ import annotations
NAME='wildcard_detection'
COUNT=6
DESCRIPTION='Internal wildcard detection capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
