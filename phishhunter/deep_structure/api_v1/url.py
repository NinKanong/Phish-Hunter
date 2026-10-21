"""API contract descriptor for Url."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/url", tags=["Url"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('url')
