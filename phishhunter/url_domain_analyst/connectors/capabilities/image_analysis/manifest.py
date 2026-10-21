from __future__ import annotations
NAME='image_analysis'
COUNT=14
DESCRIPTION='Internal image analysis capability family.'

def manifest()->dict:
    return {'name':NAME,'count':COUNT,'description':DESCRIPTION,'execution':'implemented-contract / provider-dependent where external data is required'}
