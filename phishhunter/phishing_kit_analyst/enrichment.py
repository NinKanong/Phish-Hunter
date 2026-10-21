from __future__ import annotations
from .manifest import INTEGRATIONS

def connector_plan() -> dict:
    return {"configured": [], "available": [], "catalog_only": list(INTEGRATIONS), "execution_policy": "Use only fixed, explicitly configured connectors."}

def enrich_evidence(result: dict) -> dict:
    result = dict(result or {})
    result.setdefault("enrichment", {"status": "provider_optional", "providers": {}})
    result["module_connector_plan"] = connector_plan()
    return result
