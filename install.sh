#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: sudo bash install.sh"; }
command -v python3 >/dev/null || { echo "Python 3 is required"; exit 1; }
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements/prod.txt
[[ -f .env ]] || cp .env.example .env
python -m phishhunter.seed
printf '\nPhish-Hunter-k4 installed. No demo users were created.\nCreate an administrator with: python bootstrap_admin.py --email admin@company.com --password \"Use-A-Strong-Password-Here\"\nThen start with: source .venv/bin/activate && python run.py\n'
