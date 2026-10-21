"""API contract descriptor for Ioc."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/ioc", tags=["Ioc"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('ioc')
