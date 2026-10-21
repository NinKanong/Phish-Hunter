#!/usr/bin/env python3
"""Phish-Hunter deployment helper (stdlib only).

Examples:
  python deploy_manager.py             # interactive menu
  python deploy_manager.py check       # verify source/configuration
  python deploy_manager.py setup       # create .venv and install dependencies
  python deploy_manager.py run         # run the local ASGI server
  python deploy_manager.py vercel      # run `vercel --prod` when CLI is installed
"""
from __future__ import annotations

import argparse
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
IS_WINDOWS = os.name == "nt"
VENV_PYTHON = VENV / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def run(command: list[str], *, check: bool = False) -> int:
    print("\n> " + " ".join(repr(part) if " " in part else part for part in command), flush=True)
    result = subprocess.run(command, cwd=ROOT, check=False)
    if check and result.returncode:
        raise SystemExit(result.returncode)
    return result.returncode


def print_header() -> None:
    print("\nPhish-Hunter Deployment Assistant")
    print("Project:", ROOT)
    print("Python:", sys.version.split()[0])


def check_project() -> int:
    print_header()
    required = [
        "index.py", "run.py", "pyproject.toml", "requirements.txt",
        "requirements/prod.txt", "vercel.json", "phishhunter/asgi.py",
        "phishhunter/main.py", "phishhunter/web/templates", "phishhunter/web/static",
        "phishhunter_common/hash.py", "admin/templates",
    ]
    failed = []
    for item in required:
        exists = (ROOT / item).exists()
        print(("[OK]   " if exists else "[FAIL] ") + item)
        if not exists:
            failed.append(item)
    if sys.version_info < (3, 12) or sys.version_info >= (3, 15):
        print("[WARN] Python 3.12–3.14 is recommended for the pinned dependency set.")
    else:
        print("[OK]   Supported Python minor version")
    try:
        import json
        for name in ("vercel.json",):
            json.loads((ROOT / name).read_text(encoding="utf-8"))
        print("[OK]   vercel.json parses as valid JSON")
    except Exception as exc:
        print("[FAIL] vercel.json:", exc)
        failed.append("vercel.json")
    print("\nResult:", "CHECK FAILED" if failed else "SOURCE CHECK PASSED")
    if failed:
        print("Fix the listed source/configuration issues before deployment.")
        return 1
    print("Next: run `python deploy_manager.py setup`, then `python deploy_manager.py run`.")
    return 0


def setup() -> int:
    print_header()
    if sys.version_info < (3, 12) or sys.version_info >= (3, 15):
        print("ERROR: Use Python 3.12, 3.13, or 3.14.")
        return 2
    if not VENV_PYTHON.exists():
        print("Creating an isolated virtual environment at .venv ...")
        code = run([sys.executable, "-m", "venv", str(VENV)])
        if code:
            print("ERROR: virtual environment creation failed. On Kali/Debian, install python3-venv/python3-full first.")
            return code
    if not VENV_PYTHON.exists():
        print("ERROR: expected Python executable was not created:", VENV_PYTHON)
        return 2
    for cmd in ([str(VENV_PYTHON), "-m", "pip", "install", "--upgrade", "pip"],
                [str(VENV_PYTHON), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")],
                [str(VENV_PYTHON), "-m", "pip", "check"]):
        code = run(list(cmd))
        if code:
            print("ERROR: setup stopped after a failed command. Review its output above.")
            return code
    env_file = ROOT / ".env"
    if not env_file.exists():
        sample = ROOT / ".env.example"
        contents = sample.read_text(encoding="utf-8") if sample.exists() else "APP_ENV=dev\n"
        contents = contents.replace("SECRET_KEY=replace-with-a-long-random-secret", "SECRET_KEY=" + secrets.token_urlsafe(48))
        env_file.write_text(contents, encoding="utf-8")
        print("Created .env with a fresh local SECRET_KEY (the file is git-ignored).")
    print("\nSETUP COMPLETE")
    print("Run the app with: python deploy_manager.py run")
    print("Open: http://127.0.0.1:8000")
    return 0


def run_app() -> int:
    if not VENV_PYTHON.exists():
        print("ERROR: .venv was not found. Run `python deploy_manager.py setup` first.")
        return 2
    return run([str(VENV_PYTHON), "-m", "uvicorn", "phishhunter.asgi:app", "--host", "127.0.0.1", "--port", "8000"])


def deploy_vercel() -> int:
    vercel = shutil.which("vercel") or shutil.which("vc")
    if not vercel:
        print("Vercel CLI is not installed or not on PATH.")
        print("Install Node.js/npm if needed, then run: npm install -g vercel")
        print("Authenticate once with: vercel login")
        print("Then from this project folder run: python deploy_manager.py vercel")
        print("You can also import the connected GitHub repository in the Vercel Dashboard.")
        return 2
    print("This will upload the current project and publish a production deployment.")
    answer = input("Continue with `vercel --prod`? Type YES to continue: ").strip()
    if answer != "YES":
        print("Cancelled; no deployment was run.")
        return 0
    return run([vercel, "--prod"])


def show_hosts() -> int:
    print_header()
    print("\nRecommended deployment targets")
    print("- Vercel: easiest preview/site route; serverless filesystem is ephemeral and long analysis jobs need external workers.")
    print("- Render: persistent web-service option; repository contains render.yaml.")
    print("- Railway: persistent web-service option; repository contains railway.toml.")
    print("- VPS: best when you need an always-on Python service, workers, PostgreSQL, and persistent storage.")
    print("\nUse the provider guides in deploy/ and docs/hosting-*.md.")
    print("Do not deploy .env, real secrets, private investigation files, or local databases to Git.")
    return 0


def menu() -> int:
    while True:
        print("\nPhish-Hunter Deployment Assistant")
        print("1) Check project configuration")
        print("2) Setup local Python environment")
        print("3) Run website locally")
        print("4) Deploy to Vercel production")
        print("5) Show hosting choices")
        print("0) Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            check_project()
        elif choice == "2":
            setup()
        elif choice == "3":
            run_app()
        elif choice == "4":
            deploy_vercel()
        elif choice == "5":
            show_hosts()
        elif choice == "0":
            return 0
        else:
            print("Invalid option. Choose 0–5.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Phish-Hunter setup and deployment helper")
    parser.add_argument("command", nargs="?", choices=["check", "setup", "run", "vercel", "hosts"])
    args = parser.parse_args()
    actions = {"check": check_project, "setup": setup, "run": run_app,
               "vercel": deploy_vercel, "hosts": show_hosts}
    return actions[args.command]() if args.command else menu()


if __name__ == "__main__":
    raise SystemExit(main())
