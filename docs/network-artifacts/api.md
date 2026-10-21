# Network Artifacts API

Base path: `/api/v1/pcap`

| Endpoint | Purpose |
|---|---|
| `GET /capabilities` | Artifact types and pipeline capabilities |
| `POST /upload` | Upload 1–32 artifacts and create an asynchronous job |
| `GET /jobs` | Recent job list |
| `GET /jobs/{job_id}` | Progress/result |
| `GET /jobs/{job_id}/iocs` | IOC explorer data |
| `GET /jobs/{job_id}/artifacts` | Artifact metadata |
| `GET /jobs/{job_id}/report` | Report metadata |
| `GET /jobs/{job_id}/report/{format}` | JSON/CSV/STIX/HTML export |
| `POST /jobs/{job_id}/save` | Persist completed result to authenticated account |
| `WS /ws/{job_id}` | Real-time progress |

## Access model

`GET /capabilities` is public. The upload, job, IOC, artifact and report endpoints support either:

- an authenticated account session, or
- a short-lived guest investigation session identified by the `k4_guest_id` cookie.

Guest investigations are intentionally not persisted as account scans. `POST /jobs/{job_id}/save` requires an authenticated account that owns the job.

Cookie-authenticated state-changing requests use the platform CSRF token (`X-CSRF-Token`). Bearer-token requests can be used by API clients without the browser cookie flow.

## Browser UI fallback

The repository contains a full React + TypeScript implementation under `frontend/network-artifacts/`. The server-rendered analyst page also includes a dependency-free browser implementation at `phishhunter/web/static/network-artifacts/preview.js`, so the investigation UI does not depend on Node.js being installed on the application server.
