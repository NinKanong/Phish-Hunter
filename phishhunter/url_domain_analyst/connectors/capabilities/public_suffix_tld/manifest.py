from __future__ import annotations
NAME='public_suffix_tld'
COUNT=8
DESCRIPTION='Internal public suffix tld capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
