"""API contract descriptor for Pcap."""
from fastapi import APIRouter
router=APIRouter(prefix="/api/v1/pcap", tags=["Pcap"])
@router.get("/capabilities")
def capabilities():
    from phishhunter.analysis.depth_contract import capability_manifest
    return capability_manifest('pcap')
