"""API contract descriptor for Feeds."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/feeds", tags=["Feeds"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('feeds')
