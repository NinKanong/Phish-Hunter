from __future__ import annotations
NAME='homograph_idn'
COUNT=12
DESCRIPTION='Internal homograph idn capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
