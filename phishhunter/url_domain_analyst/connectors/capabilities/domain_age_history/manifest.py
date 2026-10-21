from __future__ import annotations
NAME='domain_age_history'
COUNT=18
DESCRIPTION='Internal domain age history capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
