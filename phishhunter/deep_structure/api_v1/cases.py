"""API contract descriptor for Cases."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/cases", tags=["Cases"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('cases')
