from __future__ import annotations
from typing import Any

def build(result: dict[str, Any], deep: dict[str, Any]) -> dict[str, Any]:
    v=deep if isinstance(deep,dict) else {}
    provider_states=result.get('provider_results') if isinstance(result.get('provider_results'),dict) else {}
    configured=sum(1 for x in provider_states.values() if x not in ({},None,[]))
    sections={
      'dns': bool(v.get('dns') or result.get('dns')),
      'infrastructure': bool(v.get('infrastructure') or v.get('attack_surface',{}).get('a_records')),
      'geography': bool(v.get('geo_intelligence',{}).get('countries') or v.get('geo_intelligence',{}).get('map_points')),
      'http_tls': bool(v.get('http') or v.get('tls') or result.get('http')),
      'osint': bool(v.get('osint_deep') or v.get('pivots')),
      'c2': bool(v.get('c2_intelligence')),
      'graph': bool(v.get('graph',{}).get('nodes')),
      'evidence': bool(v.get('evidence_ledger')),
    }
    return {'status':'complete','provider_payload_groups':configured,'coverage_percent':round(sum(sections.values())/len(sections)*100), 'sections':sections,'limitations':v.get('provider_error_ledger') or []}
