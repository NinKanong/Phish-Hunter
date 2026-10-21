"""API contract descriptor for Ransomware."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/ransomware", tags=["Ransomware"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('ransomware')
