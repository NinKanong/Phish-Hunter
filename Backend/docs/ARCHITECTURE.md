# K4 Backend Architecture

```text
Browser / Workbench / Admin
        │
        ▼
FastAPI /api/v1
        │
        ├── auth / users / cases / artifacts / jobs / iocs / reports
        ▼
Services
        │
        ├── analysis ── storage ── reporting
        ▼
Repositories + SQLAlchemy Models
        │
        ├── Users / Tenants / Scans / Jobs / Artifacts
        ├── IOCs / Cases / Reports / Audit Events
        ▼
SQLite locally or configured SQLAlchemy database
```

The `Backend/` directory is intentionally a clean architectural facade. The canonical implementation remains in `phishhunter/` so existing imports, deployments and tests remain stable.
