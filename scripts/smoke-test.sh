#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash scripts/smoke-test.sh"; }
curl -fsS http://127.0.0.1:8000/health
