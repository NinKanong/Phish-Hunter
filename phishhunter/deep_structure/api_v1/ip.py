"""API contract descriptor for Ip."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/ip", tags=["Ip"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('ip')
