#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash backup.sh [DEST]"; }
DEST="${1:-backups}"
mkdir -p "$DEST"
cp -a data/phishhunter.db "$DEST/phishhunter-$(date +%Y%m%d-%H%M%S).db"
