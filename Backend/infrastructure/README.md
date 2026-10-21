# K4 Backend Infrastructure

This directory is the visible architecture boundary for infrastructure.

- SQLAlchemy database: `phishhunter/db/`
- File/evidence storage: `phishhunter/services/storage_service.py`
- Optional production services: see `docker-compose.v22.yml` and `docs/v22-unified-architecture.md`
- Deployment configuration: `deploy/` and `ops/`
