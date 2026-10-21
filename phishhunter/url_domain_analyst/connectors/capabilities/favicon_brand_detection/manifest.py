from __future__ import annotations
NAME='favicon_brand_detection'
COUNT=12
DESCRIPTION='Internal favicon brand detection capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
