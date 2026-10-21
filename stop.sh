#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash stop.sh [PORT]"; }
PORT="${1:-8000}"
pid="$(lsof -ti tcp:"$PORT" 2>/dev/null || true)"
if [[ -n "$pid" ]]; then kill "$pid"; fi
