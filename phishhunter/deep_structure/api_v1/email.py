"""API contract descriptor for Email."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/email", tags=["Email"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('email')
