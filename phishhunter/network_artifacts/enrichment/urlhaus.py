from __future__ import annotations
import os
def lookup(ioc): return {'provider':'URLhaus','ioc':ioc,'status':'not_configured' if not os.getenv('URLHAUS_API_KEY') else 'configured','result':None}
