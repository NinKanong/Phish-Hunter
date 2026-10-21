#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash scripts/backup-db.sh [DEST]"; }
bash backup.sh "${1:-backups}"
