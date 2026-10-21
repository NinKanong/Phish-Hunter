from __future__ import annotations
NAME='bgp_routing'
COUNT=10
DESCRIPTION='Internal bgp routing capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
