# K4 Unified Workbench Frontend

This is the React + TypeScript source for the v22 investigation workbench. It mirrors the backend resource boundary:

- `api/client.ts` ↔ `/api/v1/*`
- `pages/` ↔ cases, artifacts, jobs, IOCs, reports and dashboard resources
- `hooks/useLiveJob.ts` ↔ `/api/v1/jobs/ws/{job_id}`
- `store/uiStore.ts` ↔ global navigation state
- `components/` ↔ analyst UI building blocks

## Build

```bash
npm install
npm run build
```

The Vite output is configured to land in `phishhunter/web/static/workbench`.

## No Node dependency fallback

The repository also ships a dependency-free static workbench at `/workbench`. This is useful on a Windows local install when npm packages are unavailable. It calls the exact same FastAPI API and SQL-backed records.
