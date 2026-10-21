# Network Artifacts API

Base prefix: `/api/v1/pcap`

- `GET /capabilities`
- `POST /upload`
- `POST /analyze/{job_id}?access_key=...`
- `GET /jobs`
- `GET /jobs/{job_id}?access_key=...`
- `GET /jobs/{job_id}/iocs?access_key=...`
- `GET /jobs/{job_id}/artifacts?access_key=...`
- `GET /jobs/{job_id}/report?access_key=...`
- `GET /jobs/{job_id}/report/{html|pdf|json|ioc-csv|events-csv|stix}?access_key=...`
- `POST /jobs/{job_id}/save` for authenticated account jobs
- `WS /ws/{job_id}?access_key=...`

The access key is a per-investigation capability token used to make guest report/download URLs reliable even when browser cookie state is unavailable.
