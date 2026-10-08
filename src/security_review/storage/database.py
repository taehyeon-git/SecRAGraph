"""SQLAlchemy engine and session construction."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def create_database_engine(database_url: str) -> Engine:
    """Create the shared pool used by repository sessions and readiness probes."""

    return create_engine(database_url, pool_pre_ping=True)


def create_session_factory(
    database_url: str,
    *,
    engine: Engine | None = None,
) -> sessionmaker[Session]:
    """Create sessions that keep loaded reports usable after transactions close."""

    return sessionmaker(
        bind=engine or create_database_engine(database_url),
        class_=Session,
        expire_on_commit=False,
    )
