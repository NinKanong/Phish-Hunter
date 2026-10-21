# DOMINUS ULTIMATE V26 — Database / Bootstrap Hardening

## Root cause fixed

A legacy V25 SQLite database could contain an orphan `user_controls` row whose `user_id` no longer existed in `users`. Because `user_controls.user_id` is unique, a newly allocated user could receive the same numeric ID and the administrator bootstrap then failed with:

`sqlite3.IntegrityError: UNIQUE constraint failed: user_controls.user_id`

## V26 fixes

- Startup SQLite migration removes only orphan `user_controls` rows.
- Startup migration also removes orphan `user_profiles` rows.
- `bootstrap_admin.py` performs the same targeted legacy repair before provisioning.
- Bootstrap remains idempotent: running it repeatedly for the same email updates the existing administrator rather than inserting a duplicate control row.
- The distributable ZIP contains **no mutable `data/phishhunter.db`**. A clean database is created from the SQLAlchemy schema on first start.
- Added regression tests for fresh bootstrap, repeated bootstrap, and recovery from the exact orphan-control failure mode.

## Verification

- `compileall`: passed
- full pytest suite on a fresh isolated SQLite database: passed
- bootstrap integrity tests: passed
- local Uvicorn server: passed
- `/`: HTTP 200
- `/admin/login`: HTTP 200
- `/admin/health`: HTTP 200
- repeated administrator bootstrap: passed
- URL/domain quick scan (`tryhackme.com`): completed
- result page: HTTP 200
- 520 Domain Information rows rendered
- browser JavaScript syntax check: passed
- bundled world geometry: HTTP 200
- final ZIP integrity: passed

## Data integrity policy

The application does not manufacture OSINT observations. Provider-dependent intelligence remains explicitly marked unavailable/not-observed when a connector or external network is unavailable.
