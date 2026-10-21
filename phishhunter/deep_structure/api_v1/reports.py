"""API contract descriptor for Reports."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/reports", tags=["Reports"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('reports')
