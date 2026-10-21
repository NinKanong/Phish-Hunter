#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash healthcheck.sh [URL]"; }
URL="${1:-http://127.0.0.1:8000/health}"
curl -fsS "$URL"
