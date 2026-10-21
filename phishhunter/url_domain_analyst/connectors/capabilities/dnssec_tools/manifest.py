from __future__ import annotations
NAME='dnssec_tools'
COUNT=10
DESCRIPTION='Internal dnssec tools capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
