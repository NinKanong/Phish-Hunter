from __future__ import annotations
from typing import Any

CASE_SCHEMA_VERSION='phishhunter.url-domain.case.v12'

def case_metadata(result:dict[str,Any]) -> dict[str,Any]:
    return {'schema':CASE_SCHEMA_VERSION,'target':result.get('target'),'target_type':result.get('target_type'),'domain':result.get('domain'),'registered_domain':result.get('registered_domain'),'generated_at':result.get('generated_at'),'evidence_count':len(result.get('evidence') or []),'ioc_count':sum(len(v) for v in (result.get('iocs') or {}).values() if isinstance(v,list))}
