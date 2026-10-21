from __future__ import annotations
NAME='email_authentication'
COUNT=14
DESCRIPTION='Internal email authentication capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
