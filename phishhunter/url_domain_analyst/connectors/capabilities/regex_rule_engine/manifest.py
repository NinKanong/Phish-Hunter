from __future__ import annotations
NAME='regex_rule_engine'
COUNT=8
DESCRIPTION='Internal regex rule engine capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
