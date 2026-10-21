from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(command: list[str]) -> bool:
    print("$", " ".join(command))
    result = subprocess.run(command, cwd=ROOT)
    return result.returncode == 0


def main() -> int:
    checks = []
    checks.append(("compileall", run([sys.executable, "-m", "compileall", "-q", "phishhunter", "phishhunter_common"])))
    checks.append(("pytest", run([sys.executable, "-m", "pytest", "-q"])))
    deep_code = (
        "from phishhunter.web.services import SERVICE_CATALOG; "
        "from phishhunter.analysis.depth_contract import capability_manifest; "
        "from phishhunter.reports import available_report_formats; "
        "assert len(SERVICE_CATALOG) == 17; assert 'url-domain-analyst' in SERVICE_CATALOG; "
        "assert all(capability_manifest(k)['capability_count'] > 0 for k in SERVICE_CATALOG); "
        "assert len(available_report_formats()) >= 40; from phishhunter.analyzers.unified_url_domain import TOOL_CATALOG; assert len(TOOL_CATALOG) > 200; "
        "print('17 services / 40+ export formats / 200+ URL-Domain tool adapters verified')"
    )
    checks.append(("deep-contract", run([sys.executable, "-c", deep_code])))

    ruff = shutil.which("ruff")
    if ruff:
        checks.append(("ruff", run([ruff, "check", "."])))
    else:
        print("WARN: ruff executable is not installed in this build environment.")
        checks.append(("ruff", True))

    black = shutil.which("black")
    if black:
        checks.append(("black", run([black, "--check", "."])))
    else:
        print("WARN: black executable is not installed in this build environment.")
        checks.append(("black", True))

    failed = [name for name, ok in checks if not ok]
    if failed:
        print("SELF-VERIFY FAILED:", ", ".join(failed))
        return 1
    print("SELF-VERIFY PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
