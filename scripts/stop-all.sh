#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash scripts/stop-all.sh [PORT]"; }
bash stop.sh "${1:-8000}"
