"""K4 deep Email service adapter.

This package exposes the universal depth contract for email-analyst.
"""
from .engine import analyze
from .schema import SERVICE_KEY, CAPABILITIES

__all__ = ["analyze", "SERVICE_KEY", "CAPABILITIES"]
