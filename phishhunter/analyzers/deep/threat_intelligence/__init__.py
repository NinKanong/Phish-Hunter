"""K4 deep Threat Intelligence service adapter.

This package exposes the universal depth contract for threat-intelligence.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
