#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash scripts/migrate.sh"; }
python3 -m phishhunter.seed
