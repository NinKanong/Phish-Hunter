from __future__ import annotations
import json

def compact_case(result:dict)->dict:
    return {'target':result.get('target'),'risk':result.get('risk'),'executive_summary':result.get('executive_summary'),
            'key_findings':result.get('findings',[]),'graph':result.get('deep_graph') or result.get('graph'),
            'evidence':result.get('deep_evidence') or result.get('evidence'),'pivots':result.get('deep_pivots') or result.get('osint_pivots'),
            'provenance':{'engine':'Phish-Hunter URL & Domain Analyst vNext'}}

def export_json(result:dict)->str: return json.dumps(compact_case(result),sort_keys=True,indent=2,default=str)
