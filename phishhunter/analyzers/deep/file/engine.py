from __future__ import annotations

from phishhunter.analysis.deep_enhance import enhance_result
from .schema import SERVICE_KEY, CAPABILITIES

def analyze(result: dict, target: str = "") -> dict:
    """Normalize an existing service analyzer result under the K4 depth contract."""
    enriched = enhance_result(result, SERVICE_KEY, target)
    enriched["service_capabilities"] = CAPABILITIES
    return enriched
