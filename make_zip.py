from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT.parent / "Phish-Hunter-Deployment-Ready.zip"
EXCLUDED_DIRS = {
    ".git", ".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "node_modules", "build", "dist", ".vercel", "htmlcov",
}
EXCLUDED_FILES = {"phishhunter.db", "FILE_MANIFEST.json.tmp"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".log"}


def should_exclude(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    parts = rel.parts
    if any(part in EXCLUDED_DIRS for part in parts):
        return True
    if path.name in EXCLUDED_FILES or path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    if path.name == ".env" or (path.name.startswith(".env.") and not path.name.endswith(".example")):
        return True
    if any(part in {"data/storage", "reports/generated"} for part in [rel.as_posix()]):
        return True
    if rel.as_posix().startswith("data/storage/"):
        # Keep only the empty placeholder, never local captures or evidence.
        return path.name != ".gitkeep"
    if rel.as_posix().startswith("reports/generated/"):
        return True
    return False


def files_to_package() -> list[Path]:
    return sorted(path for path in ROOT.rglob("*") if path.is_file() and not should_exclude(path))


def build_manifest(paths: list[Path]) -> dict:
    manifest = {
        "project": "Phish-Hunter-k4",
        "version": "24.4.0",
        "generated_by": "make_zip.py",
        "total_files": 0,
        "languages": {"python": 0, "html": 0, "css": 0, "javascript": 0, "shell": 0, "powershell": 0, "markdown": 0, "other": 0},
        "files": [],
    }
    ext_to_lang = {".py": "python", ".html": "html", ".css": "css", ".js": "javascript", ".ts": "javascript", ".tsx": "javascript", ".sh": "shell", ".ps1": "powershell", ".md": "markdown"}
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        manifest["files"].append(rel)
        manifest["languages"][ext_to_lang.get(path.suffix.lower(), "other")] += 1
    manifest["total_files"] = len(manifest["files"])
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify and package a clean Phish-Hunter release.")
    parser.add_argument("--skip-tests", action="store_true", help="skip the full self-verification suite")
    args = parser.parse_args()
    if not args.skip_tests:
        subprocess.run([sys.executable, "self_verify.py"], cwd=ROOT, check=True)
    # The manifest is generated from the release file set. Avoid stale paths left by older releases.
    paths = files_to_package()
    manifest_path = ROOT / "FILE_MANIFEST.json"
    manifest_path.write_text(json.dumps(build_manifest(paths), indent=2) + "\n", encoding="utf-8")
    paths = files_to_package()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in paths:
            archive.write(path, path.relative_to(ROOT).as_posix())
    print(f"DONE: {OUTPUT}")
    print(f"FILES: {len(paths)}")
    print(f"SIZE: {OUTPUT.stat().st_size / (1024 * 1024):.2f} MiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
