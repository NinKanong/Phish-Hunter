from __future__ import annotations
import os
def lookup(ioc): return {'provider':'Shodan','ioc':ioc,'status':'not_configured' if not os.getenv('SHODAN_API_KEY') else 'configured','result':None}
