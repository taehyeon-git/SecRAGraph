"""Alembic environment for the SecRAGraph application schema."""

from __future__ import annotations

from logging.config import fileConfig
from os import getenv

from alembic import context
from sqlalchemy import engine_from_config, pool

from security_review.storage.intelligence import intelligence_metadata
from security_review.storage.models import Base

configuration = context.config
database_url = getenv("SECRAGRAPH_DATABASE_URL")
if database_url:
    configuration.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
if configuration.config_file_name is not None:
    fileConfig(configuration.config_file_name)

target_metadata = [Base.metadata, intelligence_metadata]


def run_migrations_offline() -> None:
    """Generate SQL without opening a database connection."""

    context.configure(
        url=configuration.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations through a short-lived unpooled engine."""

    connectable = engine_from_config(
        configuration.get_section(configuration.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, include_schemas=True
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
