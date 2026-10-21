from __future__ import annotations
NAME='llm_reasoning'
COUNT=12
DESCRIPTION='Internal llm reasoning capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
