#!/usr/bin/env bash
set -euo pipefail
usage() { echo "Usage: bash scripts/install-kvm.sh"; }
command -v kvm-ok >/dev/null 2>&1 && kvm-ok || true
