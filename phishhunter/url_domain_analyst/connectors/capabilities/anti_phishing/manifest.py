from __future__ import annotations
NAME='anti_phishing'
COUNT=14
DESCRIPTION='Internal anti phishing capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
