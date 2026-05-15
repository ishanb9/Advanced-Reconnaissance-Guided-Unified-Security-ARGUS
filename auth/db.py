"""SQLAlchemy engine, session factory, and schema bootstrap.

Provides:
    Base           — declarative base for all ORM models
    engine         — process-wide SQLAlchemy engine
    SessionLocal   — sessionmaker for short-lived units of work
    get_db()       — FastAPI dependency yielding a Session
    init_db()      — idempotent CREATE TABLE for all models

The auth module uses its OWN engine/session so that schema migrations
and connection pool tuning are independent of ARGUS's operational DB.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from auth.config import CONFIG

logger = logging.getLogger("argus.auth.db")


class Base(DeclarativeBase):
    """Declarative base for every auth-module ORM model."""


def _build_engine():
    url = CONFIG.database_url
    kwargs = {"future": True, "echo": False}

    if url.startswith("sqlite"):
        # SQLite needs check_same_thread=False for use across asyncio/threads,
        # and a StaticPool keeps a single connection alive (which is what
        # we want for the in-process FastAPI server).
        kwargs["connect_args"] = {"check_same_thread": False}
        if url == "sqlite:///:memory:":
            kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_size"] = CONFIG.db_pool_size
        kwargs["max_overflow"] = CONFIG.db_max_overflow
        kwargs["pool_pre_ping"] = True

    eng = create_engine(url, **kwargs)

    # On SQLite, enable foreign keys + WAL for better concurrency + audit-log
    # tamper resistance (WAL gives append-mostly behavior).
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _sqlite_pragmas(dbapi_conn, conn_record):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys = ON")
            cur.execute("PRAGMA journal_mode = WAL")
            cur.execute("PRAGMA synchronous = NORMAL")
            cur.execute("PRAGMA busy_timeout = 5000")
            cur.close()

    return eng


engine = _build_engine()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False,
                            expire_on_commit=False, class_=Session, future=True)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yields a DB session, ensures close on exit.

    Usage:
        @router.get("/users")
        def list_users(db: Session = Depends(get_db)):
            return db.query(User).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Sync helper: 'with session_scope() as db: ...' with commit+close."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create all tables if missing.  Safe to re-run.

    Called by integration.install_auth() on FastAPI startup.  Production
    deployments should use Alembic for schema migrations; this is the
    zero-config dev path.
    """
    # Import models lazily so the side-effect of class definition
    # registers them on Base.metadata exactly once.
    from auth import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    logger.info("auth: schema initialized (%s)", CONFIG.database_url)
