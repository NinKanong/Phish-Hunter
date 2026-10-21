"""K4 deep Reports service adapter.

This package exposes the universal depth contract for reports.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
