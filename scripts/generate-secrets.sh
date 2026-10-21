#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash scripts/generate-secrets.sh"; }
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(64))
PY
