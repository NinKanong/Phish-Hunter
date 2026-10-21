"""K4 deep Cases service adapter.

This package exposes the universal depth contract for cases.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
