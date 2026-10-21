"""API contract descriptor for Actors."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/actors", tags=["Actors"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('actors')
