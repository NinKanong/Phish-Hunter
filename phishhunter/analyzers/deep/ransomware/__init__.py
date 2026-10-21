"""K4 deep Ransomware service adapter.

This package exposes the universal depth contract for ransomware-analyst.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
