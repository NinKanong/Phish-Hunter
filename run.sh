#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash run.sh"; }
python3 -m uvicorn phishhunter.asgi:app --host 0.0.0.0 --port 8000
