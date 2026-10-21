#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash update.sh"; }
python3 -m pip install --upgrade -r requirements/prod.txt
