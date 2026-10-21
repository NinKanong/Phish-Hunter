from __future__ import annotations
NAME='tls_ssl_scanners'
COUNT=18
DESCRIPTION='Internal tls ssl scanners capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
