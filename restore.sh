#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash restore.sh DB_FILE"; }
FILE="${1:-}"
[[ -n "$FILE" ]] || { usage; exit 2; }
mkdir -p data
cp -a "$FILE" data/phishhunter.db
