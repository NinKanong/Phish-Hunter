from __future__ import annotations
import os

def lookup(ioc:str)->dict:
    return {'provider':'VirusTotal','ioc':ioc,'status':'not_configured' if not os.getenv('VT_API_KEY') else 'configured','result':None,'note':'Live lookup is intentionally not fabricated; configure VT_API_KEY and an approved connector to enable it.'}
