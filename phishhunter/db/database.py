from __future__ import annotations

from pathlib import Path
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

from phishhunter.config import settings
from phishhunter.models import Base


# Resolve relative SQLite paths from the project directory rather than from the
# process working directory. This prevents a second, empty database from being
# created when the server is launched from another folder.
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _normalize_database_url(url: str) -> tuple[str, Path | None]:
    if not url.startswith("sqlite"):
        return url, None

    # SQLAlchemy accepts sqlite:///./relative.db. Convert that path to an
    # absolute project-local path once, before the engine is created.
    prefix = "sqlite:///"
    raw_path = url[len(prefix) :] if url.startswith(prefix) else ""
    if not raw_path or raw_path in {":memory:", ":memory:"}:
        return url, None

    # A URI query string may be present (for example, ?mode=ro).
    path_part, sep, query = raw_path.partition("?")
    path = Path(path_part).expanduser()
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    else:
        path = path.resolve()

    normalized = f"sqlite:///{path.as_posix()}"
    if sep:
        normalized += f"?{query}"
    return normalized, path


database_url, SQLITE_DATABASE_PATH = _normalize_database_url(settings.database_url)

if SQLITE_DATABASE_PATH is not None:
    SQLITE_DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

connect_args = {}
if database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False, "timeout": 30}

engine = create_engine(
    database_url,
    connect_args=connect_args,
    future=True,
    pool_pre_ping=not database_url.startswith("sqlite"),
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def _safe_username(email: str, used: set[str]) -> str:
    import re
    base = (email.split("@", 1)[0] if "@" in email else email).strip().lower()
    base = re.sub(r"[^a-z0-9._-]+", "-", base).strip("._-") or "analyst"
    base = base[:56]
    candidate = base
    counter = 2
    while candidate in used:
        suffix = f"-{counter}"
        candidate = f"{base[:64-len(suffix)]}{suffix}"
        counter += 1
    used.add(candidate)
    return candidate


def _migrate_sqlite_schema() -> None:
    """Apply small additive migrations to existing SQLite databases.

    The project intentionally avoids destructive migrations: existing evidence
    remains intact while new ownership/identity columns are added and indexed.
    """
    if not database_url.startswith("sqlite"):
        return
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    additions = {
        "users": [("username", "VARCHAR(64)")],
        "scans": [("owner_user_id", "INTEGER")],
        "reports": [("owner_user_id", "INTEGER")],
        "iocs": [("owner_user_id", "INTEGER")],
        "cases": [("owner_user_id", "INTEGER")],
    }
    with engine.begin() as conn:
        for table, columns in additions.items():
            if table not in existing_tables:
                continue
            current = {c["name"] for c in inspect(conn).get_columns(table)}
            for name, definition in columns:
                if name not in current:
                    conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}'))
        if "users" in existing_tables:
            rows = conn.execute(text("SELECT id, email, username FROM users ORDER BY id ASC")).mappings().all()
            used = {str(r["username"]).strip().lower() for r in rows if r["username"]}
            for row in rows:
                if row["username"]:
                    continue
                username = _safe_username(str(row["email"]), used)
                conn.execute(text("UPDATE users SET username=:username WHERE id=:id"), {"username": username, "id": row["id"]})
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username ON users(username)"))
        # Older V18/V19/V24 development databases could contain an orphaned
        # UserControl row after a failed bootstrap transaction.  Because
        # user_controls.user_id is unique, that orphan blocks creation of the
        # real user with the same SQLite id.  It is not recoverable identity
        # state, so remove only controls that reference no existing user.
        if "user_controls" in existing_tables and "users" in existing_tables:
            conn.execute(text(
                "DELETE FROM user_controls "
                "WHERE user_id NOT IN (SELECT id FROM users)"
            ))
        if "user_profiles" in existing_tables and "users" in existing_tables:
            conn.execute(text(
                "DELETE FROM user_profiles "
                "WHERE user_id NOT IN (SELECT id FROM users)"
            ))
        for table in ("scans", "reports", "iocs", "cases"):
            if table in existing_tables:
                conn.execute(text(f'CREATE INDEX IF NOT EXISTS ix_{table}_owner_user_id ON "{table}"(owner_user_id)'))


def init_db() -> None:
    """Create every application table in the single configured database and migrate additive fields."""
    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_schema()


# Initialize the complete SQL-backed data store as soon as the application
# imports the database layer. The lifespan hook calls this again safely.
init_db()


def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
