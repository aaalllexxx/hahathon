from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import settings


connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _lightweight_migrate()


def _lightweight_migrate() -> None:
    """Idempotent additive migrations for SQLite (adds new columns when missing)."""
    from sqlalchemy import text

    pending: list[tuple[str, str, str]] = [
        ("security_checks", "origin", "VARCHAR(32) NOT NULL DEFAULT 'webhook'"),
        ("security_checks", "enforcement", "VARCHAR(64)"),
    ]
    with engine.begin() as conn:
        for table, column, ddl in pending:
            try:
                rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            except Exception:
                continue
            columns = {row[1] for row in rows}
            if column in columns:
                continue
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            except Exception:
                pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

