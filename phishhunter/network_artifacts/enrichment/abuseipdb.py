from __future__ import annotations
import os
def lookup(ioc): return {'provider':'AbuseIPDB','ioc':ioc,'status':'not_configured' if not os.getenv('ABUSEIPDB_API_KEY') else 'configured','result':None}
