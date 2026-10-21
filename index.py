"""Vercel entry point for the Phish-Hunter FastAPI application.

Vercel detects the ASGI app exported as ``app`` and routes requests to it.
For persistent production data, configure DATABASE_URL to managed PostgreSQL
and STORAGE_DIR to a persistent object-storage mount/service; Vercel's local
filesystem is ephemeral and is not suitable for durable evidence storage.
"""
from phishhunter.asgi import app

__all__ = ["app"]
