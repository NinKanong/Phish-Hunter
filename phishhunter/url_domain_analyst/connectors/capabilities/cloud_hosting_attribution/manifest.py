from __future__ import annotations
NAME='cloud_hosting_attribution'
COUNT=14
DESCRIPTION='Internal cloud hosting attribution capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
