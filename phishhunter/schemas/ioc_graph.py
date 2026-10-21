"""API schema vocabulary for IocGraph."""
from typing import Any
SERVICE_KEY='ioc-graph'
def result_schema() -> dict[str, Any]:
    return {"service": SERVICE_KEY, "required": ["findings","raw_evidence","timeline","iocs","mitre_techniques","self_verification"]}
