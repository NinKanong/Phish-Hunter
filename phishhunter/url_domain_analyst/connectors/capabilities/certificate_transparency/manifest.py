from __future__ import annotations
NAME='certificate_transparency'
COUNT=22
DESCRIPTION='Internal certificate transparency capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
