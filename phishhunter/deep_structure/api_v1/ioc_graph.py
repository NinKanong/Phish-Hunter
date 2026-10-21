"""API contract descriptor for IocGraph."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/ioc-graph", tags=["IocGraph"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('ioc-graph')
