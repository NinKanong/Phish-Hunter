"""API contract descriptor for Sandbox."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/sandbox", tags=["Sandbox"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('sandbox')
