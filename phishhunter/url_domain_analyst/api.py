from __future__ import annotations
from .engine import analyze
from .manifest import manifest
from .connectors.capability_registry import CAPABILITY_COUNT, build_capability_catalog
from .connectors.catalog import PROVIDERS
from .monitoring.watch import manifest as monitoring_manifest

def capabilities()->dict:
    return {**manifest(),'internal_capability_count':CAPABILITY_COUNT,'provider_connector_count':len(PROVIDERS),'monitoring':monitoring_manifest()}

def capability_catalog()->list[dict]: return build_capability_catalog()

def run(target,*args,**kwargs): return analyze(target,*args,**kwargs)
