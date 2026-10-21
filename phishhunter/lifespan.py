from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI

from phishhunter.config import settings
from phishhunter.db.database import SessionLocal, init_db
from phishhunter.models import GuestScan, GuestWorkspace


@asynccontextmanager
async def lifespan(app: FastAPI):
    Path(settings.storage_dir).mkdir(parents=True, exist_ok=True)
    init_db()
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc)
        db.query(GuestScan).filter(GuestScan.expires_at < cutoff).delete(synchronize_session=False)
        db.query(GuestWorkspace).filter(GuestWorkspace.created_at < cutoff - timedelta(hours=24)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    yield
