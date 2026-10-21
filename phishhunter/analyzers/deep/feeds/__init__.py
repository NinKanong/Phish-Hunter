"""K4 deep Feeds service adapter.

This package exposes the universal depth contract for feeds.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
