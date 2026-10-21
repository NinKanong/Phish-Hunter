from __future__ import annotations
NAME='threat_intel_feeds'
COUNT=32
DESCRIPTION='Internal threat intel feeds capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
