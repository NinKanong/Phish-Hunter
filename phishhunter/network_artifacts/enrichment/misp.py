from __future__ import annotations
import os
def lookup(ioc): return {'provider':'MISP','ioc':ioc,'status':'not_configured' if not os.getenv('MISP_URL') or not os.getenv('MISP_API_KEY') else 'configured','result':None}
