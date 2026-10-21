from __future__ import annotations
NAME='waf_cdn_detection'
COUNT=12
DESCRIPTION='Internal waf cdn detection capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
