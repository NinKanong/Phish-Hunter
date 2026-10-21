#!/usr/bin/env bash
set -euo pipefail
python3 -m uvicorn phishhunter.asgi:app --host 127.0.0.1 --port 8000 &
MAIN_PID=$!
python3 run_admin.py &
ADMIN_PID=$!
trap 'kill $MAIN_PID $ADMIN_PID 2>/dev/null || true' EXIT INT TERM
wait -n $MAIN_PID $ADMIN_PID
