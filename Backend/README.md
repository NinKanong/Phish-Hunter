# K4 Backend

The Backend folder is the visible backend architecture for Cyber-Phish-k4 v23.

## Connected flow

`Frontend → FastAPI → Services → Repositories/Models → SQL/Storage → Jobs/Analyzers → Scans/IOCs/Cases/Reports/Audit → Frontend + Admin`

## Important

This is an architectural facade over the tested `phishhunter/` runtime. It provides clean import points without duplicating the production implementation.

### Main entrypoint

```python
from Backend.main import app
```

### API

- `Backend/api/v1/auth.py`
- `Backend/api/v1/users.py`
- `Backend/api/v1/cases.py`
- `Backend/api/v1/artifacts.py`
- `Backend/api/v1/jobs.py`
- `Backend/api/v1/iocs.py`
- `Backend/api/v1/reports.py`
- `Backend/api/v1/health.py`
