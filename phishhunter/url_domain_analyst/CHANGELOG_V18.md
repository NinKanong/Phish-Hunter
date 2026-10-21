# V18 Runtime Reliability Repair

## What was fixed
- Added a `profile` parameter to the stable URL/domain analyzer so the web service can select `quick`, `deep`, or `forensic` without triggering a legacy `TypeError` fallback.
- Added per-collector wall-clock budgets so unavailable DNS/RDAP/CT/reputation providers cannot hang an investigation indefinitely.
- Moved the synchronous HTTP/TLS probe work off the FastAPI event loop.
- Added a system-resolver DNS fallback for A/AAAA and common record types when public DoH is unavailable.
- Added an in-process 10-minute case cache so isolated result views reuse the same completed investigation instead of launching another full scan.
- Hardened the attack-surface banner normalizer so a scalar/partial provider response cannot raise an undefined-variable exception.
- Kept provider status/provenance explicit; no provider result is fabricated.

## Verified locally
- Full pytest suite: PASS
- Python compileall: PASS
- Local `/health`: HTTP 200
- Local URL/domain workspace: HTTP 200
- Local URL/domain POST: HTTP 200
- Result contained Attack Surface, System Locations, Hosting / Networks and Services / Banners sections.
- ZIP packaging: PASS
