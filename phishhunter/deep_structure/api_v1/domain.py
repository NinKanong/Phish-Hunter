"""API contract descriptor for Domain."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/domain", tags=["Domain"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('domain')
