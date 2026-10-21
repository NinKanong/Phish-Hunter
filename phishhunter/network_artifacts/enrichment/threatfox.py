from __future__ import annotations
import os
def lookup(ioc): return {'provider':'ThreatFox','ioc':ioc,'status':'not_configured' if not os.getenv('THREATFOX_API_KEY') else 'configured','result':None}
