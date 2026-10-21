from __future__ import annotations
import os
from .connectors.catalog import catalog
from .connectors.capability_registry import CAPABILITY_COUNT

def connector_plan()->dict:
    env=dict(os.environ); rows=catalog(env)
    return {'configured':[x for x in rows if x['status']=='live-configured'],'catalog_only':[x for x in rows if x['status']=='catalog-only'],
            'internal_capability_count':CAPABILITY_COUNT,'execution_policy':'Only explicitly configured providers execute live requests.'}

def enrich_evidence(result:dict)->dict:
    result=dict(result or {}); result['module_connector_plan']=connector_plan(); return result
