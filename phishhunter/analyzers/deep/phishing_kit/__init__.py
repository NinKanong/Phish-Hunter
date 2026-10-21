"""K4 deep Phishing Kit service adapter.

This package exposes the universal depth contract for phishing-kit-analyst.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
