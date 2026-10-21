"""K4 deep Campaigns service adapter.

This package exposes the universal depth contract for campaigns.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
