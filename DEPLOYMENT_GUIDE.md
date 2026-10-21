# Phish-Hunter — deployment guide

This release keeps the active FastAPI application, existing templates/static assets, API routes, admin console, analyzers, reporting, and tool modules. The main app entrypoint is `index.py` (`from phishhunter.asgi import app`). Use the repository root as the Vercel root directory.

## Quick start with the Deployment Assistant

The assistant is stdlib-only and works in directories containing spaces (unlike shell commands assembled as strings):

```bash
python deploy_manager.py          # interactive menu
python deploy_manager.py check    # verify key files/config
python deploy_manager.py setup    # create .venv and install requirements
python deploy_manager.py run      # run local website
python deploy_manager.py hosts    # list host choices
python deploy_manager.py vercel   # deploy with Vercel CLI after confirmation
```

On Kali/Debian, do not install packages into system Python. The `setup` command creates `.venv` and invokes its Python executable directly. If venv creation is unavailable, install `python3-venv` and `python3-full` from the OS package manager first. You do not have to run `source .venv/bin/activate`; direct executable paths also avoid activation prompt problems in shell paths containing spaces.

After setup, open `http://127.0.0.1:8000`. To create the first admin on a fresh database, follow `ADMIN_SETUP.md` and use the app's bootstrap script. Do not use a real admin password in shell history on a shared machine.

## Vercel setup

1. Push the project root to GitHub; the root must contain `index.py`, `vercel.json`, `requirements.txt`, `pyproject.toml`, `phishhunter/`, and `phishhunter_common/`.
2. Import the repository in Vercel.
3. Use Root Directory `./` / repository root and the FastAPI preset (or Other if FastAPI is unavailable).
4. Leave Build Command and Output Directory as defaults. `vercel.json` defines `installCommand` as `python -m pip install -r requirements.txt` so Vercel does not try to `uv sync` and package every top-level directory.
5. Add environment variables under Project Settings and deploy.

The `pyproject.toml` explicitly restricts setuptools to `phishhunter` and `phishhunter_common`, which fixes the `Multiple top-level packages discovered in a flat-layout` build failure. The production requirements pin `psycopg[binary]` to 3.3.6 rather than the unavailable 3.2.9 pin reported by the package index.

Recommended environment variables for real use:

| Variable | Value |
|---|---|
| `APP_ENV` | `production` |
| `SECRET_KEY` | Fresh random secret, 32+ bytes entropy; store only in host settings |
| `DATABASE_URL` | Managed PostgreSQL using `postgresql+psycopg://...` |
| `PUBLIC_BASE_URL` | The deployed HTTPS origin |
| `COOKIE_SECURE` | `true` |
| `STORAGE_DIR` | Only a temporary path if using Vercel preview storage |

Do not put secrets in GitHub, source code, screenshots, or chat messages. If a secret was exposed, rotate it in the hosting environment.

Test routes on the deployed domain: `/`, `/services`, `/login`, `/health`, and `/static/workbench/index.html`. Then also test login/session flows, report export, and each analysis function you actually need.

## Hosting choice: visual preview vs full product

Vercel runs FastAPI in serverless functions. Its local disk is ephemeral; SQLite, uploaded samples, saved reports, and generated evidence are not durable. Long-running file/PCAP analysis and background workers should run on an always-on service, not a serverless web request. Vercel can host a preview or front door, but it does not make the app identical to `python run.py` on a persistent server.

For the fullest feature parity, use Render or Railway with a persistent PostgreSQL database and object storage, or a VPS with a systemd service, PostgreSQL, and durable storage. Existing provider configuration and instructions are kept in `render.yaml`, `railway.toml`, `fly.toml`, `deploy/`, and `docs/hosting-*.md`. Review the provider plan's runtime, disk, and background-job constraints before using real data.

## Troubleshooting

- `Multiple top-level packages discovered`: make sure root `pyproject.toml` has `[tool.setuptools.packages.find]`, and use the checked-in `vercel.json` rather than reverting its install command.
- `psycopg-binary==3.2.9` not found: use this release's `requirements/prod.txt` and `requirements.txt` (3.3.6).
- `externally-managed-environment` in Kali: use `python deploy_manager.py setup`, not system `pip`.
- `basename: extra operand` after activating `.venv` in a directory with spaces: this commonly comes from a custom shell prompt/plugin. Run `.venv/bin/python -m pip ...` directly (PowerShell: `.venv\Scripts\python.exe -m pip ...`) and quote paths.
- Build passes but `/health` fails: send the first runtime traceback from Vercel Functions logs. The build log and the runtime log diagnose different stages.
