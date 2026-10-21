# Cyber-Phish-k4 v22 — Unified Backend ↔ Frontend Architecture

This release turns the existing analyst features, admin control plane, SQL data model and network-artifact workbench into one connected application boundary.

## Architecture

```text
Browser / Mobile / External API
        |
        | HTTPS / WSS
        v
Reverse proxy (optional Nginx / Traefik)
        |
        +------------------------------+
        |                              |
        v                              v
FastAPI /api/v1                  Workbench frontend
        |                         React + Vite + TS source
        |                         + no-build static fallback
        v
Service + repository boundary
        |
        +---- auth / users
        +---- cases
        +---- artifacts
        +---- jobs + WebSocket
        +---- IOCs
        +---- reports
        +---- dashboard metrics
        |
        v
SQLAlchemy models
        |
        +---- users / tenants / profiles / controls
        +---- scans / cases / IOCs / reports / audit_events
        +---- analysis_jobs / artifacts
        +---- case_scans / case_artifacts
        |
        +---------------------+
        |                     |
        v                     v
SQL database             durable object storage
SQLite locally            data/storage/objects
PostgreSQL-ready          S3/MinIO adapter boundary

Optional production infrastructure:
Redis -> queue/cache/pubsub
MinIO/S3 -> evidence/reports
OpenSearch -> IOC/log search
Prometheus/Grafana/Loki/Jaeger -> observability
```

## End-to-end lifecycle

1. User signs in using the existing K4 session flow.
2. Workbench calls `/api/v1/auth/me` and `/api/v1/dashboard/summary`.
3. User uploads one or more artifacts to `/api/v1/artifacts`.
4. Upload validation calculates SHA-256 and detects the artifact type.
5. The object is stored under a tenant/job namespace.
6. `artifacts` and `analysis_jobs` rows are created in SQL.
7. The in-process analysis engine receives the same job ID.
8. `/api/v1/jobs/{job_id}/start` schedules the analysis through a FastAPI background task.
9. `/api/v1/jobs/ws/{job_id}` streams progress to the workbench.
10. On completion, the result is persisted as a `Scan`.
11. Extracted indicators are persisted as `IOC` rows.
12. A JSON `Report` is generated and linked to the source scan.
13. Audit activity records the completion event.
14. Cases can link to scans and artifacts, creating a durable investigation relationship.
15. Dashboard metrics read the same SQL records; there are no disconnected demo counters.

## Security boundary

- Passwords are hashed with the existing Argon2 implementation; password material is never rendered in the UI.
- Cookie-authenticated state-changing API calls require the K4 CSRF token.
- Tenant IDs are applied to user-facing queries.
- Uploaded files are bounded and validated before storage.
- The analysis engine is passive; the network artifact path does not execute uploaded files.
- Database credentials are not exposed by the admin UI.

## Local development

Main application:

```powershell
python .\run.py
```

Admin control center:

```powershell
python .\run_admin.py
```

Unified workbench after signing in:

```text
http://127.0.0.1:8000/workbench
```

The repository also contains the full React + TypeScript source under `frontend/app`. A static no-build workbench is included so the backend can be used without installing Node dependencies.

## Production adapters

The local default is SQLite + filesystem storage for easy development. Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL for a production database. The storage service is deliberately isolated so an S3/MinIO implementation can replace the local object adapter without changing the API contract.

Redis, OpenSearch, Prometheus, Grafana, Loki and Jaeger are infrastructure targets rather than silently assumed local dependencies. This keeps the default package runnable while preserving clear production integration boundaries.
