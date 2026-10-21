from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_bootstrap(db_path: Path, email: str = "admin@example.test"):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
    return subprocess.run(
        [sys.executable, "bootstrap_admin.py", "--email", email,
         "--password", "Strong-Admin-Password-12345!", "--organization", "K4 Test"],
        cwd=ROOT, env=env, text=True, capture_output=True,
    )


def test_bootstrap_is_idempotent(tmp_path: Path):
    db = tmp_path / "fresh.db"
    first = _run_bootstrap(db)
    second = _run_bootstrap(db)
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr

    con = sqlite3.connect(db)
    try:
        users = con.execute("SELECT id,email,is_admin FROM users").fetchall()
        controls = con.execute("SELECT user_id FROM user_controls").fetchall()
        assert users == [(1, "admin@example.test", 1)]
        assert controls == [(1,)]
    finally:
        con.close()


def test_bootstrap_repairs_legacy_orphan_control(tmp_path: Path):
    db = tmp_path / "legacy.db"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DATABASE_URL"] = f"sqlite:///{db.as_posix()}"
    setup = """
from phishhunter.db.database import SessionLocal
from phishhunter.models import UserControl
with SessionLocal() as db:
    db.add(UserControl(user_id=1))
    db.commit()
"""
    subprocess.run([sys.executable, "-c", setup], cwd=ROOT, env=env, check=True)
    result = _run_bootstrap(db, "recovered@example.test")
    assert result.returncode == 0, result.stderr
    con = sqlite3.connect(db)
    try:
        assert con.execute("SELECT COUNT(*) FROM users WHERE email='recovered@example.test'").fetchone()[0] == 1
        assert con.execute("SELECT COUNT(*) FROM user_controls WHERE user_id=1").fetchone()[0] == 1
    finally:
        con.close()
