from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from phishhunter.models import Base, User


ROOT = Path(__file__).resolve().parents[1]


def test_bootstrap_command_replaces_existing_admin_and_password(tmp_path: Path):
    db_path = tmp_path / "bootstrap.db"
    db_url = f"sqlite:///{db_path.as_posix()}"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DATABASE_URL"] = db_url

    setup = """
from phishhunter.db.database import SessionLocal
from phishhunter.models import Tenant, User
from phishhunter.security.passwords import hash_password
with SessionLocal() as db:
    tenant = Tenant(name='Existing Bootstrap')
    db.add(tenant); db.flush()
    db.add(User(tenant_id=tenant.id, email='old-admin@example.test', password_hash=hash_password('Old-Password-12345!'), is_admin=True))
    db.commit()
"""
    subprocess.run([sys.executable, "-c", setup], cwd=ROOT, env=env, check=True, text=True)

    result = subprocess.run(
        [
            sys.executable,
            "bootstrap_admin.py",
            "--email",
            "new-admin@example.test",
            "--password",
            "New-Admin-Password-12345!",
            "--organization",
            "K4 Test Org",
        ],
        cwd=ROOT,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )
    assert "Administrator ready: new-admin@example.test" in result.stdout

    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        with Session() as db:
            admins = db.query(User).filter_by(is_admin=True).all()
            assert {a.email for a in admins} == {"old-admin@example.test", "new-admin@example.test"}
            new_admin = db.query(User).filter_by(email="new-admin@example.test").one()
            assert new_admin.is_admin is True
            assert new_admin.password_hash != "New-Admin-Password-12345!"
            assert db.query(User).filter_by(email="old-admin@example.test").one().is_admin is True
    finally:
        engine.dispose()
