"""K4 deep Actors service adapter.

This package exposes the universal depth contract for actors.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
