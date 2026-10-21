from __future__ import annotations
import os
def lookup(ioc): return {'provider':'AlienVault OTX','ioc':ioc,'status':'not_configured' if not os.getenv('OTX_API_KEY') else 'configured','result':None}
