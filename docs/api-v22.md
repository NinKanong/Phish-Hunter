# v22 API Contract

Base path: `/api/v1`

## Auth

- `GET /auth/me`
- `POST /auth/logout`

## Dashboard

- `GET /dashboard/summary`

## Users (administrator)

- `GET /users`
- `POST /users`
- `PATCH /users/{user_id}`

## Cases

- `GET /cases`
- `POST /cases`
- `GET /cases/{case_id}`
- `PATCH /cases/{case_id}`
- `POST /cases/{case_id}/link-scan/{scan_id}`

## Evidence / Artifacts

- `GET /artifacts`
- `POST /artifacts` (multipart)
- `GET /artifacts/{artifact_id}`

## Jobs

- `GET /jobs`
- `GET /jobs/{job_id}`
- `POST /jobs/{job_id}/start`
- `WS /jobs/ws/{job_id}`

## Intelligence

- `GET /iocs`
- `GET /reports`
- `GET /reports/{report_id}`

## Health

- `GET /health`

The original `/api/v1/pcap/*`, `/api/v1/url`, `/api/v1/email`, `/api/v1/file`, scan detail and graph endpoints remain available for compatibility.
