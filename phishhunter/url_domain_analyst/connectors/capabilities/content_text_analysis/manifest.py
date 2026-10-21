from __future__ import annotations
NAME='content_text_analysis'
COUNT=18
DESCRIPTION='Internal content text analysis capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
