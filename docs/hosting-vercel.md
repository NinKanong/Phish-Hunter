# Hosting Phish-Hunter on Vercel

The deployable FastAPI entrypoint is the repository-root `index.py`, which exports `phishhunter.asgi:app`. Vercel's Python runtime supports FastAPI directly and treats the app as one serverless function. `vercel.json` sets the function duration and explicitly includes the Jinja templates, static assets, admin templates, and rule/spec data that the runtime reads by path. See the [official FastAPI-on-Vercel guide](https://vercel.com/docs/frameworks/backend/fastapi).

The private `api/_index.py` file is retained as a compatibility shim but is intentionally underscore-prefixed so it does not create a competing public `/api` function. Application API paths such as `/api/v1/...` are served by the root FastAPI app.

## First deployment

1. Put the contents of this repository at the root of a GitHub repository.
2. Import it into Vercel with the repository root as the Root Directory.
3. Use Python/FastAPI detection (or **Other** if a preset must be selected); do not force `frontend/app` as the project root.
4. Leave the build command and output directory empty. The site already contains its built/static assets.
5. Deploy and check `/health`, `/`, `/services`, and `/static/workbench/index.html`.

`.python-version` selects Python 3.12. The root `requirements.txt` installs production dependencies, including the PostgreSQL driver.

## Production environment variables

Configure `APP_ENV=production`, a random `SECRET_KEY`, a managed PostgreSQL `DATABASE_URL` using the `postgresql+psycopg://...` scheme, `PUBLIC_BASE_URL`, `ADMIN_BASE_URL`, and `COOKIE_SECURE=true` in Vercel. `STORAGE_DIR=/tmp/phishhunter-storage` is only a temporary fallback; it is not durable object storage.

If `DATABASE_URL` is missing, the app deliberately falls back to `/tmp/phishhunter-demo.db` so a deployment can start for visual review. Temporary SQLite data, temporary signing keys, uploads, and generated reports are not production-persistent. Configure a managed database, stable secret, and object-storage integration before using real accounts or evidence.

## Serverless limitations

Vercel does not provide persistent local disk or an always-on background worker for this app. Use an always-on host for the complete service when durable uploads/reports, long-running network-artifact analysis, queued jobs, or isolated sandbox tasks are required. Never enable public malware execution inside the web function.
