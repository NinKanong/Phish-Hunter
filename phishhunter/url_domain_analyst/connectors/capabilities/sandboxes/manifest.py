from __future__ import annotations
NAME='sandboxes'
COUNT=16
DESCRIPTION='Internal sandboxes capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
