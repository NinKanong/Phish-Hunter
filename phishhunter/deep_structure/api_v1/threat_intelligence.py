"""API contract descriptor for ThreatIntelligence."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/threat-intelligence", tags=["ThreatIntelligence"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('threat-intelligence')
