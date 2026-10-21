from __future__ import annotations
from .engine import analyze
from .manifest import manifest

def versioned_capabilities():
    m=manifest(); m['api_version']='v11'; m['routes']=['/analyze/url','/analyze/domain','/scan/{id}','/scan/{id}/graph','/domain/{d}','/url/{u}','/cert/{fp}','/ip/{ip}','/asn/{asn}','/whois/{d}','/dns/{d}','/pdns/{d}','/screenshot/{u}','/diff','/monitor','/watchlist']; return m

async def analyze_deep(target:str): return await analyze(target)
