"""K4 deep Pcap service adapter.

This package exposes the universal depth contract for pcap-analyst.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
