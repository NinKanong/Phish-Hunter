from __future__ import annotations
NAME='web_archive'
COUNT=10
DESCRIPTION='Internal web archive capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
