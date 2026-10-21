"""API contract descriptor for File."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/file", tags=["File"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('file')
