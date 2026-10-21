"""API contract descriptor for PhishingKit."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/phishing-kit", tags=["PhishingKit"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('phishing-kit')
