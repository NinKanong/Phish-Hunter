from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_FILE_NAMES = set()
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".db", ".sample"}
FORBIDDEN_DIR_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv"}
PLACEHOLDERS = ("NotImplemented" + "Error", "rest " + "of code here", "omitted " + "for brevity", "similar " + "to above")


def main() -> int:
    errors: list[str] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if path.is_dir() and path.name in FORBIDDEN_DIR_NAMES:
            errors.append(f"forbidden runtime directory: {rel}")
        if path.is_file():
            if path.name in FORBIDDEN_FILE_NAMES:
                errors.append(f"forbidden container artifact: {rel}")
            if path.suffix.lower() in FORBIDDEN_SUFFIXES:
                errors.append(f"runtime artifact: {rel}")
            if path.suffix.lower() in {".py", ".ps1", ".sh", ".toml", ".yaml", ".yml"}:
                text = path.read_text(encoding="utf-8", errors="replace")
                for marker in PLACEHOLDERS:
                    if marker in text:
                        errors.append(f"placeholder marker {marker!r}: {rel}")
                if path.name == "install.ps1":
                    if "sys.version_info" in text or "f{" in text or "print({}" in text:
                        errors.append("install.ps1 still embeds brittle Python version-formatting code")
                    if "Get-PythonCandidate" not in text or "python -V" not in text:
                        errors.append("install.ps1 does not use robust PowerShell version detection")
    manifest_path = ROOT / "FILE_MANIFEST.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        version_file = ROOT / "phishhunter" / "version.py"
        version_text = version_file.read_text(encoding="utf-8")
        expected = manifest.get("version")
        if expected and f'APP_VERSION = "{expected}"' not in version_text:
            errors.append(f"manifest/version mismatch: {expected}")
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PACKAGE_VERIFY_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
